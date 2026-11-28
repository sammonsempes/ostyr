.globl _start
_start:
    mov $295, %eax
    mov $-100, %ebx
    mov 8(%esp), %ecx
    mov $0x41, %edx
    mov $420, %esi
    int $0x80
    mov $5, %eax
    mov 12(%esp), %ebx
    mov $0x41, %ecx
    mov $420, %edx
    int $0x80
    mov $8, %eax
    mov 16(%esp), %ebx
    mov $420, %ecx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
