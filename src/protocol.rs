//! # VPN Protocol Module
//!
//! ЛУЧШАЯ ПРАКТИКА: Type-safe протокол
//! - Все типы пакетов явно определены
//! - Сериализация/десериализация безопасны
//! - Версионирование для совместимости

use crate::error::{ProtocolError, Result};
use crate::{PROTOCOL_VERSION, PROTOCOL_HEADER_SIZE, CHACHA20_NONCE_SIZE};

/// Типы пакетов VPN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    /// Handshake инициация
    HandshakeInit = 1,
    /// Handshake ответ
    HandshakeResponse = 2,
    /// Зашифрованные данные
    Data = 3,
    /// Keep-alive
    Keepalive = 4,
    /// Запрос на отключение
    Disconnect = 5,
}

impl PacketType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(PacketType::HandshakeInit),
            2 => Ok(PacketType::HandshakeResponse),
            3 => Ok(PacketType::Data),
            4 => Ok(PacketType::Keepalive),
            5 => Ok(PacketType::Disconnect),
            _ => Err(ProtocolError::InvalidPacketType(value).into()),
        }
    }
}

/// Заголовок пакета VPN
///
/// Формат (24 байта):
/// ```text
/// ┌────────┬────────┬────────────┬──────────────────────────┐
/// │ Version│  Type  │  Counter   │         Nonce            │
/// │ (1 byte)│(1 byte)│ (4 bytes)  │       (12 bytes)         │
/// └────────┴────────┴────────────┴──────────────────────────┘
/// │ Reserved (6 bytes)                                       │
/// └──────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub version: u8,
    pub packet_type: PacketType,
    pub counter: u32,
    pub nonce: [u8; CHACHA20_NONCE_SIZE],
}

impl PacketHeader {
    pub fn new(packet_type: PacketType, counter: u32) -> Self {
        let mut nonce = [0u8; CHACHA20_NONCE_SIZE];
        // Nonce = counter (4 bytes) + random (8 bytes)
        nonce[0..4].copy_from_slice(&counter.to_le_bytes());
        // В реальности здесь должен быть криптографически безопасный random
        // Для образовательных целей используем простой timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        nonce[4..12].copy_from_slice(&timestamp.to_le_bytes());
        
        PacketHeader {
            version: PROTOCOL_VERSION,
            packet_type,
            counter,
            nonce,
        }
    }

    pub fn serialize(&self) -> [u8; PROTOCOL_HEADER_SIZE] {
        let mut buf = [0u8; PROTOCOL_HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.packet_type as u8;
        buf[2..6].copy_from_slice(&self.counter.to_le_bytes());
        buf[6..18].copy_from_slice(&self.nonce);
        // bytes 18-23 reserved
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < PROTOCOL_HEADER_SIZE {
            return Err(ProtocolError::PacketTooSmall {
                min: PROTOCOL_HEADER_SIZE,
                got: buf.len(),
            }.into());
        }

        let version = buf[0];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                got: version,
            }.into());
        }

        let packet_type = PacketType::from_u8(buf[1])?;
        let counter = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let mut nonce = [0u8; CHACHA20_NONCE_SIZE];
        nonce.copy_from_slice(&buf[6..18]);

        Ok(PacketHeader {
            version,
            packet_type,
            counter,
            nonce,
        })
    }
}

/// Полный VPN пакет
#[derive(Debug)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Создаёт новый пакет данных
    pub fn new_data(counter: u32, payload: Vec<u8>) -> Self {
        Packet {
            header: PacketHeader::new(PacketType::Data, counter),
            payload,
        }
    }

    /// Создаёт keepalive пакет
    pub fn new_keepalive(counter: u32) -> Self {
        Packet {
            header: PacketHeader::new(PacketType::Keepalive, counter),
            payload: Vec::new(),
        }
    }

    /// Создаёт handshake init пакет
    pub fn new_handshake_init(counter: u32, client_pubkey: [u8; 32]) -> Self {
        Packet {
            header: PacketHeader::new(PacketType::HandshakeInit, counter),
            payload: client_pubkey.to_vec(),
        }
    }

    /// Сериализует пакет
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROTOCOL_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.serialize());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Десериализует пакет
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let header = PacketHeader::deserialize(buf)?;
        let payload = buf[PROTOCOL_HEADER_SIZE..].to_vec();
        Ok(Packet { header, payload })
    }

    /// Возвращает полный размер пакета
    pub fn size(&self) -> usize {
        PROTOCOL_HEADER_SIZE + self.payload.len()
    }
}

// ЛУЧШАЯ ПРАКТИКА: Anti-replay защита
/// Sliding window для защиты от replay атак
#[derive(Debug)]
pub struct ReplayWindow {
    /// Последний принятый counter
    last_counter: u64,
    /// Битовая маска для окна (64 пакета)
    bitmap: u64,
    /// Размер окна
    window_size: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow {
            last_counter: 0,
            bitmap: 0,
            window_size: 64,
        }
    }

    /// Проверяет, является ли пакет replay-атакой
    /// Возвращает true если пакет валиден (не replay)
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false; // Counter 0 зарезервирован
        }

        if counter > self.last_counter {
            // Новый пакет вперёди окна
            let diff = counter - self.last_counter;
            if diff >= self.window_size {
                // Полностью новое окно
                self.bitmap = 1;
            } else {
                // Сдвигаем окно
                self.bitmap <<= diff;
                self.bitmap |= 1;
            }
            self.last_counter = counter;
            return true;
        }

        // Пакет в пределах окна или до него
        let diff = self.last_counter - counter;
        if diff >= self.window_size {
            // Слишком старый пакет
            return false;
        }

        // Проверяем бит в маске
        let bit = 1u64 << diff;
        if self.bitmap & bit != 0 {
            // Уже видели этот пакет
            return false;
        }

        // Отмечаем пакет как принятый
        self.bitmap |= bit;
        true
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let packet = Packet::new_data(42, b"Hello VPN!".to_vec());
        let serialized = packet.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        
        assert_eq!(packet.header.counter, deserialized.header.counter);
        assert_eq!(packet.payload, deserialized.payload);
    }

    #[test]
    fn test_replay_window() {
        let mut window = ReplayWindow::new();
        
        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(window.check_and_update(3));
        
        // Replay
        assert!(!window.check_and_update(2));
        
        // Out of order но в окне
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(4));
        
        // Снова replay
        assert!(!window.check_and_update(4));
    }
}
