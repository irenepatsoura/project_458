import time
import os
from Crypto.Cipher import AES as PyCryptoAES

# =============================================================================
# SHARED CONSTANTS
# =============================================================================

# Standard AES S-Box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# =============================================================================
# 1. VULNERABLE AES IMPLEMENTATION (Naive / Table-Based)
# =============================================================================

class VulnerableAES:
    """
    Naive implementation of AES (First Round Only for demonstration).
    
    It performs:
    1. AddRoundKey
    2. SubBytes (using a lookup table)
    
    VULNERABILITY:
    The SubBytes step involves a table lookup: SBOX[index].
    In a real system, the time to access memory depends on whether the address
    is in the cache. This creates a timing side-channel.
    
    We simulate this by adding a delay inside `sub_bytes` that depends on the value.
    """
    def __init__(self, key):
        self.key = key
        self.sbox = SBOX

    def _simulate_cache_latency(self, byte_val: int) -> int:
        """
        Simulates the timing difference of a Cache Miss vs Cache Hit.
        
        - byte_val > 200: Simulated Cache Miss (Slow)
        - byte_val == 0 : Special case (Very Slow)
        - else          : Cache Hit (Fast)
        """
        dummy = 0
        if byte_val > 200:
            # Slow path (Cache Miss)
            for x in range(20):
                dummy += x
        elif byte_val == 0:
            # Very slow path
            for x in range(30):
                dummy += x
        else:
            # Fast path (Cache Hit)
            for x in range(2):
                dummy += x
        return dummy

    def sub_bytes(self, state: bytearray) -> bytearray:
        """
        Apply S-Box substitution to each byte.
        INJECTS TIMING LEAK.
        """
        for i in range(16):
            val = state[i]
            
            # The vulnerability: Access time depends on the value (index)
            self._simulate_cache_latency(val)
            
            # Actual S-Box lookup
            state[i] = self.sbox[val]
        return state

    def add_round_key(self, state: bytearray, key: bytes) -> bytearray:
        """
        XOR state with the key.
        """
        for i in range(16):
            state[i] ^= key[i]
        return state

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts a single block (Simplified AES).
        """
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes")

        state = bytearray(plaintext)
        
        # 1. AddRoundKey (Initial)
        # Note: In a full AES, we would expand the key. Here we use the raw key.
        state = self.add_round_key(state, self.key)
        
        # 2. SubBytes (Round 1)
        # This is where the leak happens. The input to S-Box is (Plaintext ^ Key).
        state = self.sub_bytes(state)
        
        # (ShiftRows and MixColumns omitted for this timing demo as they don't add S-Box leaks)
        
        return bytes(state)


# =============================================================================
# 2. CONSTANT-TIME TOY IMPLEMENTATION (Algebraic S-box)
# =============================================================================

class CTToyAES:
    """
    Constant-time implementation using an algebraic S-box.
    
    It performs the same structure:
    1. AddRoundKey
    2. SubBytes (using calculation, not table lookup)
    """
    def __init__(self, key):
        self.key = key

    def _simulate_cache_latency_ct(self, byte_val: int) -> int:
        """
        Constant-time dummy work.
        Always does the same amount of work regardless of input.
        """
        dummy = 0
        for x in range(30): # Matches worst-case of Vulnerable
            dummy += x ^ byte_val
        return dummy

    def _algebraic_sbox(self, x: int) -> int:
        """
        Computes S-Box value using bitwise operations (Constant Time).
        """
        x &= 0xFF
        y = (x * 17) & 0xFF
        r1 = ((x << 1) | (x >> 7)) & 0xFF
        r2 = ((x << 2) | (x >> 6)) & 0xFF
        y ^= r1
        y ^= r2
        y ^= 0x5A
        return y

    def sub_bytes(self, state: bytearray) -> bytearray:
        for i in range(16):
            val = state[i]
            
            # Constant-time dummy work
            self._simulate_cache_latency_ct(val)
            
            # Algebraic S-Box (No table lookup)
            state[i] = self._algebraic_sbox(val)
        return state

    def add_round_key(self, state: bytearray, key: bytes) -> bytearray:
        for i in range(16):
            state[i] ^= key[i]
        return state

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) != 16:
            raise ValueError("Plaintext must be 16 bytes")

        state = bytearray(plaintext)
        
        # 1. AddRoundKey
        state = self.add_round_key(state, self.key)
        
        # 2. SubBytes (Constant Time)
        state = self.sub_bytes(state)
        
        return bytes(state)


# =============================================================================
# 3. SAFE AES IMPLEMENTATION (PyCryptodome, hardware AES if available)
# =============================================================================

class SafeAES:
    """
    Wrapper for PyCryptodome AES (MODE_ECB).
    PyCryptodome uses constant-time code, and on x86 it typically uses AES-NI
    if the CPU and build support it.
    """
    def __init__(self, key):
        self.cipher = PyCryptoAES.new(key, PyCryptoAES.MODE_ECB)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(plaintext)


# =============================================================================
# 4. EXPERIMENTAL HARNESS
# =============================================================================

def measure_time(encrypt_func, plaintext: bytes, num_runs: int = 100) -> float:
    """
    Measure average execution time of encrypt_func(plaintext) in nanoseconds,
    similar to Python's time.perf_counter_ns().
    """
    timer = time.perf_counter_ns

    # Warm-up
    encrypt_func(plaintext)

    start = timer()
    for _ in range(num_runs):
        encrypt_func(plaintext)
    end = timer()

    return (end - start) / num_runs
