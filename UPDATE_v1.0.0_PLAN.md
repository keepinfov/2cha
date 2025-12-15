# План реализации улучшений протокола 2cha VPN

## Оглавление

1. [Обзор текущего состояния](#1-обзор-текущего-состояния)
2. [Фаза 1: Криптографическая модернизация](#фаза-1-криптографическая-модернизация)
3. [Фаза 2: Новый протокол рукопожатия](#фаза-2-новый-протокол-рукопожатия)
4. [Фаза 3: Оптимизация производительности](#фаза-3-оптимизация-производительности)
5. [Фаза 4: Устойчивость к нестабильным сетям](#фаза-4-устойчивость-к-нестабильным-сетям)
6. [Фаза 5: Управление доступом и идентификация](#фаза-5-управление-доступом-и-идентификация)
7. [Фаза 6: Мобильная оптимизация](#фаза-6-мобильная-оптимизация)
8. [Фаза 7: Тестирование и миграция](#фаза-7-тестирование-и-миграция)
9. [Риски и митигации](#риски-и-митигации)
10. [Временная оценка](#временная-оценка)

---

## 1. Обзор текущего состояния

### 1.1 Анализ существующей архитектуры

**Текущие компоненты:**
- Статический симметричный ключ (32 байта), общий для всех клиентов
- ChaCha20-Poly1305 / AES-256-GCM для шифрования данных
- Заголовок пакета 24 байта: Version(1) + Type(1) + Counter(4) + Nonce(12) + Reserved(6)
- Генерация nonce через `/dev/urandom` для каждого пакета
- Простая replay-защита через sliding window (64 бита)
- UDP-транспорт с TUN-интерфейсом

**Выявленные проблемы:**
1. Единый ключ для всех клиентов — компрометация одного раскрывает всех
2. Невозможность отзыва доступа отдельного клиента
3. Избыточная нагрузка от чтения `/dev/urandom` на каждый пакет
4. Отсутствие Perfect Forward Secrecy (PFS)
5. Жёсткие таймауты без адаптации к качеству канала
6. Нет механизма автоматического переподключения
7. Высокое энергопотребление на мобильных устройствах

### 1.2 Целевая архитектура

```
┌─────────────────────────────────────────────────────────────────┐
│                    2cha Protocol v4                              │
├─────────────────────────────────────────────────────────────────┤
│  Идентификация: Ed25519 (статические ключи)                     │
│  Согласование: X25519 (эфемерные ключи)                         │
│  Шифрование: ChaCha20-Poly1305 (сессионные ключи)               │
│  Рукопожатие: Noise_IK (1-RTT, взаимная аутентификация)         │
│  Транспорт: UDP с опциональным TCP fallback                     │
│  Управление: Whitelist/Blacklist/Open modes                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Фаза 1: Криптографическая модернизация

### 1.1 Добавление криптографических примитивов

**Задача 1.1.1: Интеграция Ed25519**
- Добавить зависимость `ed25519-dalek` или `ring` для Ed25519
- Создать модуль `src/core/crypto/identity.rs`:
  - Генерация ключевой пары Ed25519
  - Сериализация/десериализация ключей
  - Подпись и верификация сообщений
  - Конвертация Ed25519 → X25519 (для DH)

**Задача 1.1.2: Интеграция X25519**
- Использовать `x25519-dalek` для Diffie-Hellman
- Создать модуль `src/core/crypto/key_exchange.rs`:
  - Генерация эфемерных ключей X25519
  - Выполнение DH-обмена
  - Вывод сессионного ключа через HKDF

**Задача 1.1.3: Key Derivation Function**
- Интегрировать HKDF-SHA256 из `hkdf` crate
- Создать модуль `src/core/crypto/kdf.rs`:
  - Вывод симметричных ключей из DH-результата
  - Поддержка chaining для множественных DH
  - Вывод отдельных ключей для TX/RX направлений

### 1.2 Структуры ключей

**Задача 1.2.1: Формат хранения ключей**
```
Структура файла ключа (.2cha-key):
┌────────────────────────────────────────┐
│ Magic: "2CHA" (4 bytes)                │
│ Version: u8                            │
│ Key Type: u8 (0=static, 1=ephemeral)   │
│ Creation Time: u64 (Unix timestamp)    │
│ Private Key: [u8; 32]                  │
│ Public Key: [u8; 32]                   │
│ Checksum: [u8; 4] (CRC32)              │
└────────────────────────────────────────┘
```

**Задача 1.2.2: CLI для управления ключами**
- Расширить команду `genkey`:
  - `2cha genkey --type ed25519` — новый формат (по умолчанию)
  - `2cha genkey --type symmetric` — legacy совместимость
  - `2cha pubkey <private-key-file>` — извлечение публичного ключа
  - `2cha keyinfo <key-file>` — информация о ключе

**Задача 1.2.3: Миграция конфигурации**
- Обновить структуры `CryptoSection`:
  ```
  [crypto]
  # Новый формат
  private_key_file = "/etc/2cha/server.key"
  # Для клиента — дополнительно публичный ключ сервера
  server_public_key = "base64-encoded-32-bytes"
  
  # Legacy (deprecated, но поддерживается)
  key = "hex-encoded-symmetric-key"
  ```

### 1.3 Обратная совместимость

**Задача 1.3.1: Версионирование протокола**
- Protocol Version 3 → текущий (симметричный ключ)
- Protocol Version 4 → новый (асимметричные ключи)
- Сервер должен поддерживать оба на переходный период

**Задача 1.3.2: Автодетект версии**
- Определение версии по первому байту пакета рукопожатия
- Fallback на legacy при необходимости
- Логирование использования deprecated режима

---

## Фаза 2: Новый протокол рукопожатия

### 2.1 Noise_IK Pattern

**Теоретическая основа:**
```
Noise_IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

Где:
- `s` — статический ключ (Ed25519 → X25519)
- `e` — эфемерный ключ (X25519)
- `es`, `ee`, `se`, `ss` — DH операции

**Задача 2.1.1: Создать модуль `src/core/protocol/handshake.rs`**

Структуры сообщений:

```
HandshakeInit (Client → Server):
┌──────────────────────────────────────────────────────┐
│ Version: u8 = 4                                      │
│ Type: u8 = 1 (HandshakeInit)                         │
│ Sender Index: u32 (уникальный ID сессии клиента)     │
│ Ephemeral Public: [u8; 32]                           │
│ Encrypted Static: [u8; 48] (32 + 16 tag)             │
│ Encrypted Timestamp: [u8; 28] (12 + 16 tag)          │
│ MAC1: [u8; 16]                                       │
│ MAC2: [u8; 16] (заполняется при DoS защите)          │
└──────────────────────────────────────────────────────┘
Размер: 148 байт

HandshakeResponse (Server → Client):
┌──────────────────────────────────────────────────────┐
│ Version: u8 = 4                                      │
│ Type: u8 = 2 (HandshakeResponse)                     │
│ Sender Index: u32                                    │
│ Receiver Index: u32                                  │
│ Ephemeral Public: [u8; 32]                           │
│ Encrypted Empty: [u8; 16] (только tag)              │
│ MAC1: [u8; 16]                                       │
│ MAC2: [u8; 16]                                       │
└──────────────────────────────────────────────────────┘
Размер: 92 байта
```

**Задача 2.1.2: Реализация состояний рукопожатия**

```
enum HandshakeState {
    // Клиент
    ClientInitSent { 
        ephemeral_private: X25519SecretKey,
        timestamp: u64,
        sender_index: u32,
    },
    
    // Сервер
    ServerWaitingInit,
    ServerResponseSent {
        ephemeral_private: X25519SecretKey,
        peer_index: u32,
        session_keys: SessionKeys,
    },
    
    // Общее
    Established {
        session: EstablishedSession,
    },
}

struct SessionKeys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce_counter: u64,
    recv_nonce_counter: u64,
}
```

**Задача 2.1.3: Криптографическая цепочка (Chaining Key)**
- Инициализация: `ck = HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")`
- После каждого DH: `(ck, k) = HKDF(ck, DH_result)`
- Финальные ключи: `(send_key, recv_key) = HKDF(ck, "")`

### 2.2 Защита от DoS атак

**Задача 2.2.1: MAC1 — базовая проверка**
- `MAC1 = HMAC-BLAKE2s(HASH(server_public_key), packet[0..116])`
- Дешёвая проверка до дорогих криптооперацій

**Задача 2.2.2: MAC2 — Cookie Challenge**
- При высокой нагрузке сервер отправляет Cookie Reply
- `Cookie = AEAD(random_secret, client_ip || timestamp)`
- `MAC2 = HMAC-BLAKE2s(Cookie, packet[0..132])`
- Клиент должен повторить запрос с валидным MAC2

**Задача 2.2.3: Rate Limiting**
- Создать модуль `src/core/protection/rate_limit.rs`:
  - Ограничение handshake запросов по IP
  - Token bucket алгоритм
  - Автоматическое включение cookie challenge при превышении порога

### 2.3 Обновление формата Data пакетов

**Задача 2.3.1: Новый заголовок Data пакета**
```
Data Packet (v4):
┌──────────────────────────────────────────────────────┐
│ Type: u8 = 4 (Data)                                  │
│ Receiver Index: u32                                  │
│ Counter: u64                                         │
│ Encrypted Payload: [u8; N + 16]                      │
└──────────────────────────────────────────────────────┘
Overhead: 13 + 16 = 29 байт (vs 24 + 16 = 40 в v3)
```

**Задача 2.3.2: Детерминированный Nonce**
- Nonce = `little_endian(counter)` + `[0u8; 4]` (12 байт)
- Убрать random nonce generation полностью
- Counter инкрементируется для каждого пакета

---

## Фаза 3: Оптимизация производительности

### 3.1 Устранение узких мест в криптографии

**Задача 3.1.1: Кэширование RNG**
- Заменить чтение `/dev/urandom` на каждый пакет
- Создать `ThreadLocalRng` с периодическим reseed
- Для nonce использовать детерминированный counter (см. 2.3.2)

**Задача 3.1.2: Оптимизация ChaCha20-Poly1305**
- Проверить включение SIMD оптимизаций:
  ```toml
  [dependencies]
  chacha20poly1305 = { version = "0.10", features = ["std"] }
  ```
- Добавить runtime detection AVX2/NEON
- Бенчмарки для различных размеров пакетов

**Задача 3.1.3: Переиспользование криптообъектов**
- Cipher instance должен создаваться один раз на сессию
- Избегать аллокаций в hot path
- Использовать `encrypt_in_place` где возможно

### 3.2 Оптимизация I/O

**Задача 3.2.1: Batch Processing**
- Реализовать `recvmmsg`/`sendmmsg` обёртки:
  ```rust
  struct BatchBuffer {
      messages: Vec<mmsghdr>,
      iovecs: Vec<iovec>,
      addrs: Vec<sockaddr_storage>,
      buffers: Vec<[u8; MTU]>,
  }
  
  impl BatchBuffer {
      fn recv_batch(&mut self, socket: RawFd) -> io::Result<usize>;
      fn send_batch(&mut self, socket: RawFd) -> io::Result<usize>;
  }
  ```
- Настраиваемый `batch_size` (default: 32-64)

**Задача 3.2.2: Multi-Queue TUN**
- Полная реализация IFF_MULTI_QUEUE:
  - Несколько file descriptors для одного TUN
  - Распределение по CPU cores
  - Affinity binding для потоков

**Задача 3.2.3: Zero-Copy где возможно**
- Использовать `writev`/`readv` для vectored I/O
- Избегать промежуточных копирований между TUN и UDP
- Рассмотреть `io_uring` для Linux 5.1+:
  ```rust
  #[cfg(feature = "io-uring")]
  mod io_uring_backend {
      // Асинхронный I/O без системных вызовов на каждый пакет
  }
  ```

### 3.3 Многопоточность

**Задача 3.3.1: Архитектура потоков**
```
┌─────────────────────────────────────────────────────────────┐
│                    Main Thread                               │
│  - Signal handling                                          │
│  - Configuration reload                                     │
│  - Session management                                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
       ┌───────────────┼───────────────┐
       ▼               ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Worker 0    │ │ Worker 1    │ │ Worker N    │
│ - TUN queue │ │ - TUN queue │ │ - TUN queue │
│ - UDP sock  │ │ - UDP sock  │ │ - UDP sock  │
│ - Sessions  │ │ - Sessions  │ │ - Sessions  │
└─────────────┘ └─────────────┘ └─────────────┘
```

**Задача 3.3.2: Session Sharding**
- Распределение сессий по воркерам на основе hash(peer_index)
- Lock-free очереди между потоками
- Минимизация contention на общих структурах

**Задача 3.3.3: CPU Affinity**
- Реализовать `cpu_affinity` из конфигурации
- Привязка IRQ к соответствующим CPU (документация)
- Изоляция polling потоков

---

## Фаза 4: Устойчивость к нестабильным сетям

### 4.1 Таймеры и переподключение

**Задача 4.1.1: Адаптивные таймауты**
- Создать модуль `src/core/timing.rs`:
  ```rust
  struct AdaptiveTimer {
      base_interval: Duration,
      current_interval: Duration,
      max_interval: Duration,
      backoff_factor: f64,
      jitter_range: f64,
  }
  
  impl AdaptiveTimer {
      fn next_with_jitter(&mut self) -> Duration;
      fn reset(&mut self);
      fn backoff(&mut self);
  }
  ```

**Задача 4.1.2: Периодический Re-Keying**
- Инициировать новое рукопожатие:
  - Каждые 2 минуты (REKEY_AFTER_TIME)
  - После 2^64 - 2^16 пакетов (REKEY_AFTER_MESSAGES)
  - При отсутствии ответа 15 секунд (REKEY_TIMEOUT)
- Graceful transition между старой и новой сессией

**Задача 4.1.3: Keepalive стратегия**
```
Состояния keepalive:
┌─────────────────────────────────────────────────────────────┐
│ ACTIVE: трафик есть → не отправлять keepalive              │
│ IDLE: нет трафика > KEEPALIVE_TIMEOUT → отправить          │
│ PASSIVE_KEEPALIVE: получен keepalive → ответить если нужно │
│ DEAD: нет ответа > 3*KEEPALIVE → rehandshake               │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Roaming Support

**Задача 4.2.1: Endpoint Update**
- При получении валидного пакета с нового адреса:
  - Проверить session index и counter
  - Обновить endpoint без rehandshake
  - Логировать смену адреса

**Задача 4.2.2: Dual-Stack Failover**
- Поддержка одновременного IPv4 и IPv6
- При недоступности одного стека — переключение на другой
- Happy Eyeballs алгоритм для выбора

### 4.3 Буферизация и Congestion

**Задача 4.3.1: Intelligent Buffering**
- Адаптивный размер буферов на основе RTT:
  ```rust
  struct DynamicBuffer {
      min_size: usize,
      max_size: usize,
      current_size: usize,
      rtt_estimator: RttEstimator,
  }
  ```

**Задача 4.3.2: Simple Congestion Avoidance**
- Отслеживание packet loss через счётчики
- Уменьшение batch size при высоком loss
- Экспоненциальный backoff для retransmit handshake

---

## Фаза 5: Управление доступом и идентификация

### 5.1 Режимы доступа

**Задача 5.1.1: Конфигурация режимов**
```toml
[access]
# Режим: "whitelist" | "blacklist" | "open"
mode = "whitelist"

# Для whitelist — разрешённые публичные ключи
allowed_keys = [
    "base64-key-1",
    "base64-key-2",
]

# Для blacklist — заблокированные ключи
blocked_keys = [
    "base64-key-3",
]

# Файлы со списками (опционально)
allowed_keys_file = "/etc/2cha/allowed.keys"
blocked_keys_file = "/etc/2cha/blocked.keys"
```

**Задача 5.1.2: Runtime управление**
- Unix socket для управления:
  - `2cha-ctl add-peer <public-key> [name]`
  - `2cha-ctl remove-peer <public-key>`
  - `2cha-ctl list-peers`
  - `2cha-ctl block-peer <public-key>`
- Без перезапуска сервера

**Задача 5.1.3: Key Revocation**
- При добавлении ключа в blacklist:
  - Немедленное отключение активной сессии
  - Отправка Disconnect пакета
  - Отказ в новых handshake

### 5.2 Идентификация клиентов

**Задача 5.2.1: Peer Database**
```rust
struct PeerConfig {
    public_key: [u8; 32],
    name: Option<String>,
    allowed_ips: Vec<IpNet>,  // Разрешённые source IP для этого peer
    created_at: SystemTime,
    last_handshake: Option<SystemTime>,
    transfer_rx: u64,
    transfer_tx: u64,
}

struct PeerDatabase {
    peers: HashMap<[u8; 32], PeerConfig>,
    // Индекс для быстрого поиска по allowed_ips
    ip_to_peer: HashMap<IpAddr, [u8; 32]>,
}
```

**Задача 5.2.2: Per-Peer IP Assignment**
- Автоматическое назначение IP из пула:
  ```toml
  [ipv4]
  pool = "10.0.0.0/24"
  
  [[peers]]
  public_key = "..."
  allowed_ips = ["10.0.0.2/32"]  # Статический или автоматический
  ```

### 5.3 Аудит и логирование

**Задача 5.3.1: Security Events**
- Логировать:
  - Успешные/неуспешные handshake с peer identity
  - Смена endpoint (roaming)
  - Key revocation events
  - Replay attack attempts

**Задача 5.3.2: Metrics Export**
- Prometheus-compatible metrics:
  ```
  2cha_peers_active{server="main"} 42
  2cha_handshakes_total{status="success"} 1234
  2cha_handshakes_total{status="failed"} 56
  2cha_bytes_received{peer="base64key"} 123456789
  ```

---

## Фаза 6: Мобильная оптимизация

### 6.1 Энергоэффективность

**Задача 6.1.1: Батарея-aware таймеры**
```rust
enum PowerMode {
    Normal,      // Обычные интервалы
    PowerSave,   // Увеличенные интервалы keepalive
    Aggressive,  // Минимальная латентность
}

impl PowerMode {
    fn keepalive_interval(&self) -> Duration {
        match self {
            Normal => Duration::from_secs(25),
            PowerSave => Duration::from_secs(180),
            Aggressive => Duration::from_secs(10),
        }
    }
}
```

**Задача 6.1.2: Интеграция с системой**
- Android: использование `AlarmManager` для keepalive
- iOS: Background App Refresh интеграция
- Документация для мобильных разработчиков

**Задача 6.1.3: Минимизация wakeups**
- Coalescing таймеров
- Batch processing накопленных пакетов
- Отложенная отправка non-critical данных

### 6.2 Сетевые особенности мобильных сетей

**Задача 6.2.1: NAT Keepalive**
- Уменьшенный интервал для мобильных NAT (часто < 30 сек)
- Детектирование NAT timeout и адаптация
- Пустые keepalive пакеты (минимальный размер)

**Задача 6.2.2: Network Change Detection**
- Переподключение при смене сети (WiFi ↔ Cellular)
- Сохранение session state во время переключения
- Immediate handshake на новом интерфейсе

**Задача 6.2.3: MTU Discovery**
- PMTUD для определения оптимального MTU
- Автоматическое уменьшение при ICMP Fragmentation Needed
- Default MTU 1280 для мобильных (IPv6 minimum)

### 6.3 Оптимизация кода для ARM

**Задача 6.3.1: NEON оптимизации**
- Проверить компиляцию с `target-feature=+neon`
- Бенчмарки на реальных ARM устройствах
- Fallback для старых устройств без NEON

**Задача 6.3.2: Memory footprint**
- Профилирование использования памяти
- Ограничение количества одновременных сессий
- Lazy loading конфигурации

---

## Фаза 7: Тестирование и миграция

### 7.1 Тестовое покрытие

**Задача 7.1.1: Unit Tests**
- Криптографические примитивы:
  - Key generation
  - DH exchange
  - AEAD encrypt/decrypt
  - KDF derivation
- Протокол:
  - Handshake state machine
  - Packet serialization
  - Replay window

**Задача 7.1.2: Integration Tests**
- Client-Server handshake flow
- Data transmission
- Reconnection scenarios
- Roaming simulation

**Задача 7.1.3: Fuzzing**
- Packet parser fuzzing (libFuzzer/AFL)
- Handshake state machine fuzzing
- Malformed input handling

**Задача 7.1.4: Performance Benchmarks**
```rust
#[bench]
fn bench_handshake_full() { ... }

#[bench]
fn bench_encrypt_1500_bytes() { ... }

#[bench]
fn bench_batch_recv_64_packets() { ... }
```

### 7.2 Криптографический аудит

**Задача 7.2.1: Документация протокола**
- Формальная спецификация нового протокола
- Security considerations
- Comparison с WireGuard

**Задача 7.2.2: Внешний аудит**
- Подготовка кода к аудиту
- Контакт с криптографическими аудиторами
- Исправление найденных проблем

### 7.3 Миграция пользователей

**Задача 7.3.1: Migration Guide**
- Пошаговая инструкция обновления
- Автоматический конвертер конфигурации:
  ```bash
  2cha migrate-config old-config.toml > new-config.toml
  ```
- Скрипт генерации ключей для существующих клиентов

**Задача 7.3.2: Dual-Mode Period**
- Сервер поддерживает v3 и v4 одновременно
- Warning при использовании v3
- Планируемая дата deprecation

**Задача 7.3.3: Rollback Plan**
- Сохранение старых конфигураций
- Процедура отката при проблемах
- Канал связи для срочных issues

---

## Риски и митигации

| Риск | Вероятность | Влияние | Митигация |
|------|-------------|---------|-----------|
| Критическая уязвимость в новом handshake | Низкая | Критическое | Использование проверенного Noise framework, аудит |
| Потеря совместимости со старыми клиентами | Средняя | Среднее | Dual-mode период, автоматическая миграция |
| Регрессия производительности | Средняя | Среднее | Continuous benchmarking, A/B тестирование |
| Сложность реализации | Высокая | Среднее | Поэтапная разработка, code review |
| Проблемы на специфичных платформах | Средняя | Низкое | Расширенное тестирование на целевых платформах |

---

## Временная оценка

| Фаза | Задачи | Оценка (недели) | Зависимости |
|------|--------|-----------------|-------------|
| **Фаза 1**: Криптография | 1.1, 1.2, 1.3 | 3-4 | — |
| **Фаза 2**: Handshake | 2.1, 2.2, 2.3 | 4-5 | Фаза 1 |
| **Фаза 3**: Производительность | 3.1, 3.2, 3.3 | 3-4 | Фаза 2 |
| **Фаза 4**: Устойчивость | 4.1, 4.2, 4.3 | 2-3 | Фаза 2 |
| **Фаза 5**: Управление доступом | 5.1, 5.2, 5.3 | 2-3 | Фаза 2 |
| **Фаза 6**: Мобильная оптимизация | 6.1, 6.2, 6.3 | 2-3 | Фаза 3, 4 |
| **Фаза 7**: Тестирование | 7.1, 7.2, 7.3 | 4-6 | Все предыдущие |
| **Итого** | | **20-28 недель** | |

---

## Приоритизация задач

### Must Have (MVP)
- [x] Фаза 1.1: Ed25519/X25519 интеграция
- [x] Фаза 2.1: Базовый Noise_IK handshake
- [x] Фаза 3.1.1: Устранение /dev/urandom на пакет
- [x] Фаза 5.1: Базовый whitelist режим
- [x] Фаза 7.1: Unit tests для криптографии

### Should Have
- [ ] Фаза 2.2: DoS защита с cookies
- [ ] Фаза 3.2: Batch processing
- [ ] Фаза 4.1: Адаптивные таймауты
- [ ] Фаза 4.2: Roaming support
- [ ] Фаза 5.2: Runtime управление peers

### Nice to Have
- [ ] Фаза 3.2.3: io_uring backend
- [ ] Фаза 3.3: Полная многопоточность
- [ ] Фаза 5.3: Prometheus metrics
- [ ] Фаза 6: Полная мобильная оптимизация

---

## Контрольные точки (Milestones)

1. **M1**: Криптографический фундамент готов (Фаза 1 завершена)
2. **M2**: Рабочий handshake между клиентом и сервером (Фаза 2 завершена)
3. **M3**: Производительность на уровне или лучше текущей (Фаза 3 завершена)
4. **M4**: Стабильная работа на нестабильных сетях (Фаза 4 завершена)
5. **M5**: Полная система управления доступом (Фаза 5 завершена)
6. **M6**: Релиз-кандидат с полным тестированием (Фаза 7 завершена)
