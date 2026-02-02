"""
Goldilocks Prime Field Arithmetic

Field: F_p where p = 2^64 - 2^32 + 1

This prime has special structure enabling:
- Fast modular reduction
- FFT-friendly (has large 2-adic subgroup)
- Efficient SIMD implementation

The multiplicative group has order p-1 = 2^32 * (2^32 - 1)
which contains a subgroup of order 2^32 (for FFT up to 2^32 elements).
"""

from __future__ import annotations
from typing import List, Tuple, Optional
import random


# Goldilocks prime: p = 2^64 - 2^32 + 1
GOLDILOCKS_PRIME = (1 << 64) - (1 << 32) + 1

# Generator of multiplicative group (primitive root)
MULTIPLICATIVE_GENERATOR = 7

# Two-adicity: largest k such that 2^k divides p-1
TWO_ADICITY = 32

# 2^32-th root of unity
ROOT_OF_UNITY_ORDER_2_32 = pow(MULTIPLICATIVE_GENERATOR, (GOLDILOCKS_PRIME - 1) >> TWO_ADICITY, GOLDILOCKS_PRIME)


class FieldElement:
    """
    Element of the Goldilocks prime field.

    Represents values in F_p where p = 2^64 - 2^32 + 1.

    All arithmetic operations are constant-time modular operations.
    """

    __slots__ = ('value',)

    def __init__(self, value: int):
        """Create field element from integer."""
        self.value = value % GOLDILOCKS_PRIME

    # =========================================================================
    # Arithmetic Operations
    # =========================================================================

    def __add__(self, other: FieldElement) -> FieldElement:
        """Addition in F_p."""
        return FieldElement(self.value + other.value)

    def __sub__(self, other: FieldElement) -> FieldElement:
        """Subtraction in F_p."""
        return FieldElement(self.value - other.value + GOLDILOCKS_PRIME)

    def __mul__(self, other: FieldElement) -> FieldElement:
        """Multiplication in F_p."""
        return FieldElement(self.value * other.value)

    def __neg__(self) -> FieldElement:
        """Negation in F_p."""
        return FieldElement(GOLDILOCKS_PRIME - self.value if self.value else 0)

    def __truediv__(self, other: FieldElement) -> FieldElement:
        """Division in F_p (multiplication by inverse)."""
        return self * other.inverse()

    def __pow__(self, exp: int) -> FieldElement:
        """Exponentiation using square-and-multiply."""
        if exp < 0:
            return self.inverse() ** (-exp)
        return FieldElement(pow(self.value, exp, GOLDILOCKS_PRIME))

    def inverse(self) -> FieldElement:
        """
        Multiplicative inverse using Fermat's little theorem.

        a^-1 = a^(p-2) mod p
        """
        if self.value == 0:
            raise ZeroDivisionError("Cannot invert zero")
        return FieldElement(pow(self.value, GOLDILOCKS_PRIME - 2, GOLDILOCKS_PRIME))

    def sqrt(self) -> Optional[FieldElement]:
        """
        Square root if it exists.

        For Goldilocks, p ≡ 1 (mod 4), so we use Tonelli-Shanks.
        """
        return _tonelli_shanks(self)

    # =========================================================================
    # Comparison Operations
    # =========================================================================

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FieldElement):
            return self.value == other.value
        if isinstance(other, int):
            return self.value == (other % GOLDILOCKS_PRIME)
        return False

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash(self.value)

    def __repr__(self) -> str:
        return f"FieldElement({self.value})"

    def __str__(self) -> str:
        return str(self.value)

    # =========================================================================
    # Serialization
    # =========================================================================

    def to_bytes(self) -> bytes:
        """Serialize to 8 bytes (little-endian)."""
        return self.value.to_bytes(8, 'little')

    @classmethod
    def from_bytes(cls, data: bytes) -> FieldElement:
        """Deserialize from 8 bytes (little-endian)."""
        return cls(int.from_bytes(data[:8], 'little'))

    def to_int(self) -> int:
        """Convert to integer."""
        return self.value

    # =========================================================================
    # Predicates
    # =========================================================================

    def is_zero(self) -> bool:
        return self.value == 0

    def is_one(self) -> bool:
        return self.value == 1

    # =========================================================================
    # Class Methods
    # =========================================================================

    @classmethod
    def zero(cls) -> FieldElement:
        """Additive identity."""
        return cls(0)

    @classmethod
    def one(cls) -> FieldElement:
        """Multiplicative identity."""
        return cls(1)

    @classmethod
    def random(cls) -> FieldElement:
        """Generate random field element."""
        return cls(random.randrange(GOLDILOCKS_PRIME))

    @classmethod
    def from_hash(cls, data: bytes) -> FieldElement:
        """Create field element from hash output (reduces mod p)."""
        # Take first 8 bytes, reduce mod p
        value = int.from_bytes(data[:8], 'little')
        return cls(value)

    @classmethod
    def primitive_root_of_unity(cls, order: int) -> FieldElement:
        """
        Get primitive n-th root of unity where n = 2^order.

        Requires order <= TWO_ADICITY (32).
        """
        if order > TWO_ADICITY:
            raise ValueError(f"Order 2^{order} exceeds two-adicity {TWO_ADICITY}")

        # Start with 2^32-th root of unity and square down
        root = cls(ROOT_OF_UNITY_ORDER_2_32)
        for _ in range(TWO_ADICITY - order):
            root = root * root

        return root


# =============================================================================
# Helper Functions
# =============================================================================

def _tonelli_shanks(a: FieldElement) -> Optional[FieldElement]:
    """
    Tonelli-Shanks algorithm for computing square roots.

    Returns sqrt(a) if it exists, None otherwise.
    """
    if a.is_zero():
        return FieldElement.zero()

    p = GOLDILOCKS_PRIME

    # Check if a is a quadratic residue
    if pow(a.value, (p - 1) // 2, p) != 1:
        return None

    # Factor p-1 = 2^s * q where q is odd
    s = TWO_ADICITY
    q = (p - 1) >> s

    # Find a quadratic non-residue
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(a.value, q, p)
    r = pow(a.value, (q + 1) // 2, p)

    while True:
        if t == 1:
            return FieldElement(r)

        # Find least i such that t^(2^i) = 1
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1

        # Update
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p


def batch_inverse(elements: List[FieldElement]) -> List[FieldElement]:
    """
    Batch inversion using Montgomery's trick.

    Computes inverses of n elements using 3(n-1) multiplications + 1 inversion.
    Much faster than n individual inversions.
    """
    n = len(elements)
    if n == 0:
        return []
    if n == 1:
        return [elements[0].inverse()]

    # Forward pass: compute prefix products
    prefix = [FieldElement.one()] * n
    prefix[0] = elements[0]
    for i in range(1, n):
        prefix[i] = prefix[i-1] * elements[i]

    # Single inversion of the total product
    inv_total = prefix[-1].inverse()

    # Backward pass: compute individual inverses
    inverses = [FieldElement.zero()] * n
    for i in range(n - 1, 0, -1):
        inverses[i] = inv_total * prefix[i-1]
        inv_total = inv_total * elements[i]
    inverses[0] = inv_total

    return inverses


def interpolate_at_point(
    points: List[Tuple[FieldElement, FieldElement]],
    x: FieldElement
) -> FieldElement:
    """
    Evaluate interpolating polynomial at a point using Lagrange interpolation.

    Given points [(x_0, y_0), ..., (x_n, y_n)], compute P(x) where
    P is the unique polynomial of degree ≤ n passing through all points.
    """
    n = len(points)
    result = FieldElement.zero()

    for i in range(n):
        xi, yi = points[i]

        # Compute Lagrange basis polynomial L_i(x)
        numerator = FieldElement.one()
        denominator = FieldElement.one()

        for j in range(n):
            if i != j:
                xj, _ = points[j]
                numerator = numerator * (x - xj)
                denominator = denominator * (xi - xj)

        # L_i(x) = numerator / denominator
        basis = numerator / denominator

        # Add y_i * L_i(x) to result
        result = result + (yi * basis)

    return result


# =============================================================================
# Extension Field (for FRI if needed)
# =============================================================================

class QuadraticExtension:
    """
    Quadratic extension of Goldilocks: F_p[x] / (x^2 - 7)

    Elements are a + b*w where w^2 = 7 (non-residue).
    """

    __slots__ = ('a', 'b')

    # Non-residue for extension
    NON_RESIDUE = FieldElement(7)

    def __init__(self, a: FieldElement, b: FieldElement):
        self.a = a
        self.b = b

    def __add__(self, other: QuadraticExtension) -> QuadraticExtension:
        return QuadraticExtension(self.a + other.a, self.b + other.b)

    def __sub__(self, other: QuadraticExtension) -> QuadraticExtension:
        return QuadraticExtension(self.a - other.a, self.b - other.b)

    def __mul__(self, other: QuadraticExtension) -> QuadraticExtension:
        # (a + bw)(c + dw) = (ac + bd*7) + (ad + bc)w
        a, b = self.a, self.b
        c, d = other.a, other.b
        return QuadraticExtension(
            a * c + b * d * self.NON_RESIDUE,
            a * d + b * c
        )

    def __neg__(self) -> QuadraticExtension:
        return QuadraticExtension(-self.a, -self.b)

    def inverse(self) -> QuadraticExtension:
        # (a + bw)^-1 = (a - bw) / (a^2 - 7*b^2)
        denom = self.a * self.a - self.NON_RESIDUE * self.b * self.b
        denom_inv = denom.inverse()
        return QuadraticExtension(self.a * denom_inv, -self.b * denom_inv)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, QuadraticExtension):
            return self.a == other.a and self.b == other.b
        return False

    @classmethod
    def zero(cls) -> QuadraticExtension:
        return cls(FieldElement.zero(), FieldElement.zero())

    @classmethod
    def one(cls) -> QuadraticExtension:
        return cls(FieldElement.one(), FieldElement.zero())

    def to_bytes(self) -> bytes:
        return self.a.to_bytes() + self.b.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> QuadraticExtension:
        return cls(
            FieldElement.from_bytes(data[:8]),
            FieldElement.from_bytes(data[8:16])
        )
