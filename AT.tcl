big_endian

uint8 version
uint8 type
set desc_size [uint8 desc_size]
if { $desc_size > 0 } {
    ascii $desc_size desc
}

set hash_size [uint8 hash_size]
if { $hash_size > 0 } {
    hex $hash_size hash
}

uint64 expiry_ms

set extension_count [uint16 extension_count]
if { $extension_count > 0 } {
    section extensions {
        for {set i 1} {$i <= $extension_count} {incr i} {
            uint8 type
            set size [uint16 size]
            bytes $size data
        }
    }
}