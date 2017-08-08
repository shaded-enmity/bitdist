#include <Python.h>

#define Py_REPR(x) PyBytes_AsString(PyUnicode_AsASCIIString(PyObject_Repr(x)))

#define IMPL_XOR(num)                                                          \
  void xor_aligned##num(char *left, char *right, char *result,                 \
                        Py_ssize_t size) {                                     \
    char *restrict left_buf = __builtin_assume_aligned(left, num);             \
    char *restrict right_buf = __builtin_assume_aligned(right, num);           \
    char *restrict result_buf = __builtin_assume_aligned(result, num);         \
    Py_ssize_t i = 0;                                                          \
                                                                               \
    for (i = 0; i < size; ++i)                                                 \
      result_buf[i] = left_buf[i] ^ right_buf[i];                              \
  }

#define ALIGNED_XOR_BASE(val)                                                  \
  if ((left_sz & (val - 1)) == 0) {                                            \
    xor_aligned##val(left_buf, right_buf, result_buf, left_sz);                \
  }

#define ALIGNED_XOR_CASE(val)                                                  \
  else ALIGNED_XOR_BASE(val)

IMPL_XOR(8);
IMPL_XOR(16);
IMPL_XOR(32);

#ifdef __x86_64
/* up to 32-byte unrolled implementation of popcount, see:
 * http://danluu.com/assembly-intrinsics/
 **/
uint64_t popcnt64_fast(const uint64_t *p, size_t len) {
  size_t i;
  uint64_t cnt[4] = {0}, c, mask;

  c = 0;
  mask = len & ~3;

  /* 4x unrolled loop */
  for (i = 0; i < mask; i += 4)
    __asm__("popcnt %4, %4  \n\t"
            "add %4, %0     \n\t"
            "popcnt %5, %5  \n\t"
            "add %5, %1     \n\t"
            "popcnt %6, %6  \n\t"
            "add %6, %2     \n\t"
            "popcnt %7, %7  \n\t"
            "add %7, %3     \n\t"
            : "+r"(cnt[0]), "+r"(cnt[1]), "+r"(cnt[2]), "+r"(cnt[3])
            : "r"(p[i]), "r"(p[i + 1]), "r"(p[i + 2]), "r"(p[i + 3]));

  /* add the remaining items (max 3) */
  for (i = 0; i < (len & 3); ++i)
    __asm__("popcnt %1, %1  \n\t"
            "add %1, %0     \n\t"
            : "+r"(c)
            : "r"(p[mask + i]));

  /* sum across the vector and add the remaining bits */
  return cnt[0] + cnt[1] + cnt[2] + cnt[3] + c;
}
#else

#ifdef __aarch64__

uint64_t popcnt64_fast(const uint64_t *p, size_t len) {
  unsigned long long *d = p;
  unsigned int masked = 0, i = 0;
  int c = 0;

  masked = len & ~3;
  for (; i < masked; i += 4)
    __asm__("LD1 {v0.2D, v1.2D}, [%1], #32    \n\t"
            "CNT v0.16b, v0.16b               \n\t"
            "CNT v1.16b, v1.16b               \n\t"
            "UADDLV h2, v0.16b                \n\t"
            "UADDLV h3, v1.16b                \n\t"
            "ADD d2, d3, d2                   \n\t"
            "UMOV x0, v2.d[0]                 \n\t"
            "ADD %0, x0, %0                   \n\t"
            : "+r"(c), "+r"(d)
            :: "x0", "v0", "v1", "v2", "v3");

  for (; i < len; ++i)
    __asm__("LD1  {v0.D}[0], [%1], #8 \n\t"
            "CNT  v0.8b, v0.8b        \n\t"
            "UADDLV h1, v0.8b         \n\t"
            "UMOV x0, v1.d[0]         \n\t"
            "ADD %0, x0, %0           \n\t"
            : "+r"(c), "+r"(d)
            :: "x0", "v0", "v1");

  return c;
}

#else

#error "Unknown architecture"

#endif
#endif

static PyObject *compute_bit_dist(PyObject *self, PyObject *args) {
  PyObject *left = NULL, *right = NULL;
  Py_ssize_t left_sz = 0, right_sz = 0;
  char *left_buf = NULL, *right_buf = NULL, *result_buf = NULL;
  uint64_t count = 0;

  /* unpack 2 objects from the args */
  if (!PyArg_ParseTuple(args, "OO", &left, &right))
    Py_RETURN_NONE;
  /* make sure both are bytes */
  if (!PyBytes_Check(left) || !PyBytes_Check(right)) {
    char *left_t = Py_REPR((PyObject *)left->ob_type), 
         *right_t = Py_REPR((PyObject *)right->ob_type);
    PyErr_SetObject(PyExc_RuntimeError,
                    PyUnicode_FromFormat("arguments are not bytes (left: %s, right: %s)", 
                                         left_t, right_t));
    return NULL;
  }

  left_sz = PyBytes_Size(left);
  right_sz = PyBytes_Size(right);

  /* check that both bytes() are of the same size */
  if (left_sz != right_sz) {
    PyErr_SetString(PyExc_RuntimeError,
                    ("input arguments do not have the same cardinality"));
    return NULL;
  }

  /* data are not aligned at uint64_t boundary */
  if ((left_sz & 7) != 0) {
    PyErr_SetString(PyExc_RuntimeError,
                    ("input arguments are not 8 byte aligned"));
    return NULL;
  }

  /* sanity check, make sure that we don't
   * try to process arrays bigger than 2^61, since
   * it might, in a worst case scenario overflow
   * the counter buffer:
   *
   * popcnt(0 ^ 255) == 8
   * 8 * 2^61 == 2^64
   * QED
   *
   * (now figure out from where to allocate 3×2^61 buffers)
   */
  if (left_sz > ((Py_ssize_t)1 << 61)) {
    PyErr_SetString(PyExc_RuntimeError, ("input arguments are too big"));
    return NULL;
  }

  result_buf = malloc(left_sz);
  if (!result_buf) {
    PyErr_SetString(PyExc_RuntimeError,
                    ("out of memory allocating result buffer"));
    return NULL;
  }

  /* get hold of the underlying pointers */
  left_buf = PyBytes_AsString(left);
  right_buf = PyBytes_AsString(right);

  /* call specific per-alignment function */
  ALIGNED_XOR_BASE(32)
  ALIGNED_XOR_CASE(16)
  ALIGNED_XOR_CASE(8)

  /* popcnt64_fast expects size in units of uin64_t so we divide by 8 */
  count = popcnt64_fast((const uint64_t *)result_buf, left_sz >> 3);
  free(result_buf);

  /* return as unsigned long long */
  return Py_BuildValue("K", count);
}

static PyMethodDef BDM[] = {
    {"bit_dist", compute_bit_dist, METH_VARARGS, "computes bit distance between two bytes buffers"},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef bitdist = {PyModuleDef_HEAD_INIT, "bitdist", "", -1,
                                     BDM};

PyMODINIT_FUNC PyInit_bitdist(void) { return PyModule_Create(&bitdist); }
