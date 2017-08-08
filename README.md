# bitdist

Fast implementation of bit distance for Python3 on `x86_64` or `aarch64`:

```python
>>> import bitdist
>>> bitdist.bit_dist(b'00000001', b'00000000')
1
>>> bitdist.bit_dist(b'00000003', b'00000000')
2
>>> bitdist.bit_dist(b'00000007', b'00000003')
1
```
