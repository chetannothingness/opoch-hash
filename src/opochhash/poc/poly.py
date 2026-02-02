"""
Polynomial Operations and FFT

Provides:
- Polynomial arithmetic over the Goldilocks field
- Fast Fourier Transform (FFT) and inverse FFT
- Polynomial interpolation and evaluation
- Low-degree extension for STARK
"""

from typing import List, Tuple, Optional
from .field import FieldElement, GOLDILOCKS_PRIME, batch_inverse


class Polynomial:
    """
    Polynomial over the Goldilocks field.

    Represented as coefficient list where coeffs[i] is the coefficient of x^i.
    """

    def __init__(self, coeffs: List[FieldElement]):
        """
        Create polynomial from coefficients.

        Args:
            coeffs: Coefficient list [a_0, a_1, ..., a_n] for a_0 + a_1*x + ... + a_n*x^n
        """
        # Remove trailing zeros
        while coeffs and coeffs[-1].is_zero():
            coeffs.pop()
        self.coeffs = coeffs if coeffs else [FieldElement.zero()]

    @property
    def degree(self) -> int:
        """Degree of polynomial (-1 for zero polynomial)."""
        if len(self.coeffs) == 1 and self.coeffs[0].is_zero():
            return -1
        return len(self.coeffs) - 1

    def is_zero(self) -> bool:
        """Check if polynomial is zero."""
        return self.degree == -1

    # =========================================================================
    # Arithmetic Operations
    # =========================================================================

    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        """Add two polynomials."""
        max_len = max(len(self.coeffs), len(other.coeffs))
        result = []
        for i in range(max_len):
            a = self.coeffs[i] if i < len(self.coeffs) else FieldElement.zero()
            b = other.coeffs[i] if i < len(other.coeffs) else FieldElement.zero()
            result.append(a + b)
        return Polynomial(result)

    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        """Subtract two polynomials."""
        max_len = max(len(self.coeffs), len(other.coeffs))
        result = []
        for i in range(max_len):
            a = self.coeffs[i] if i < len(self.coeffs) else FieldElement.zero()
            b = other.coeffs[i] if i < len(other.coeffs) else FieldElement.zero()
            result.append(a - b)
        return Polynomial(result)

    def __mul__(self, other: 'Polynomial') -> 'Polynomial':
        """Multiply two polynomials (naive O(n^2))."""
        if self.is_zero() or other.is_zero():
            return Polynomial([FieldElement.zero()])

        result_len = len(self.coeffs) + len(other.coeffs) - 1
        result = [FieldElement.zero()] * result_len

        for i, a in enumerate(self.coeffs):
            for j, b in enumerate(other.coeffs):
                result[i + j] = result[i + j] + (a * b)

        return Polynomial(result)

    def __neg__(self) -> 'Polynomial':
        """Negate polynomial."""
        return Polynomial([-c for c in self.coeffs])

    def scale(self, scalar: FieldElement) -> 'Polynomial':
        """Multiply by scalar."""
        return Polynomial([c * scalar for c in self.coeffs])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Polynomial):
            return False
        if len(self.coeffs) != len(other.coeffs):
            return False
        return all(a == b for a, b in zip(self.coeffs, other.coeffs))

    # =========================================================================
    # Evaluation
    # =========================================================================

    def evaluate(self, x: FieldElement) -> FieldElement:
        """
        Evaluate polynomial at a point using Horner's method.

        Time complexity: O(n)
        """
        if not self.coeffs:
            return FieldElement.zero()

        result = self.coeffs[-1]
        for i in range(len(self.coeffs) - 2, -1, -1):
            result = result * x + self.coeffs[i]
        return result

    def evaluate_domain(self, domain: List[FieldElement]) -> List[FieldElement]:
        """
        Evaluate polynomial at all points in domain.

        For power-of-2 domains with primitive root, use FFT for O(n log n).
        Otherwise, O(n^2) naive evaluation.
        """
        return [self.evaluate(x) for x in domain]

    # =========================================================================
    # Division
    # =========================================================================

    def divmod(self, divisor: 'Polynomial') -> Tuple['Polynomial', 'Polynomial']:
        """
        Polynomial division with remainder.

        Returns (quotient, remainder) such that self = quotient * divisor + remainder
        """
        if divisor.is_zero():
            raise ZeroDivisionError("Cannot divide by zero polynomial")

        if self.degree < divisor.degree:
            return Polynomial([FieldElement.zero()]), self

        quotient = [FieldElement.zero()] * (self.degree - divisor.degree + 1)
        remainder = self.coeffs[:]

        divisor_lead_inv = divisor.coeffs[-1].inverse()

        for i in range(len(quotient) - 1, -1, -1):
            if len(remainder) < len(divisor.coeffs) + i:
                continue

            coeff = remainder[len(divisor.coeffs) + i - 1] * divisor_lead_inv
            quotient[i] = coeff

            for j in range(len(divisor.coeffs)):
                idx = i + j
                if idx < len(remainder):
                    remainder[idx] = remainder[idx] - coeff * divisor.coeffs[j]

        # Remove trailing zeros from remainder
        while remainder and remainder[-1].is_zero():
            remainder.pop()
        if not remainder:
            remainder = [FieldElement.zero()]

        return Polynomial(quotient), Polynomial(remainder)

    def __truediv__(self, other: 'Polynomial') -> 'Polynomial':
        """Division (quotient only)."""
        q, _ = self.divmod(other)
        return q

    def __mod__(self, other: 'Polynomial') -> 'Polynomial':
        """Modulo (remainder only)."""
        _, r = self.divmod(other)
        return r

    # =========================================================================
    # Interpolation
    # =========================================================================

    @staticmethod
    def interpolate(points: List[Tuple[FieldElement, FieldElement]]) -> 'Polynomial':
        """
        Lagrange interpolation from (x, y) points.

        Time complexity: O(n^2)
        """
        n = len(points)
        if n == 0:
            return Polynomial([FieldElement.zero()])

        # Build the polynomial using Lagrange basis
        result = Polynomial([FieldElement.zero()])

        for i in range(n):
            xi, yi = points[i]

            # Build L_i(x) = ∏_{j≠i} (x - x_j) / (x_i - x_j)
            basis = Polynomial([FieldElement.one()])
            denominator = FieldElement.one()

            for j in range(n):
                if i != j:
                    xj, _ = points[j]
                    # Multiply by (x - x_j)
                    basis = basis * Polynomial([-xj, FieldElement.one()])
                    # Accumulate denominator
                    denominator = denominator * (xi - xj)

            # Divide by denominator and multiply by y_i
            basis = basis.scale(yi / denominator)
            result = result + basis

        return result

    @staticmethod
    def from_evaluations_fft(
        evaluations: List[FieldElement],
        domain: List[FieldElement]
    ) -> 'Polynomial':
        """
        Interpolate from evaluations using inverse FFT.

        Requires domain to be [ω^0, ω^1, ..., ω^{n-1}] for primitive root ω.
        """
        return ifft_to_poly(evaluations)

    # =========================================================================
    # Special Polynomials
    # =========================================================================

    @staticmethod
    def zerofier(domain: List[FieldElement]) -> 'Polynomial':
        """
        Compute zerofier polynomial: Z(x) = ∏(x - d) for d in domain.

        Z(x) = 0 for all x in domain.
        """
        result = Polynomial([FieldElement.one()])
        for d in domain:
            result = result * Polynomial([-d, FieldElement.one()])
        return result

    @staticmethod
    def vanishing_poly(n: int, omega: FieldElement) -> 'Polynomial':
        """
        Vanishing polynomial for domain {1, ω, ω^2, ..., ω^{n-1}}.

        Z(x) = x^n - 1
        """
        coeffs = [FieldElement.zero()] * (n + 1)
        coeffs[0] = -FieldElement.one()
        coeffs[n] = FieldElement.one()
        return Polynomial(coeffs)

    # =========================================================================
    # Serialization
    # =========================================================================

    def to_bytes(self) -> bytes:
        """Serialize polynomial."""
        parts = [len(self.coeffs).to_bytes(4, 'big')]
        for c in self.coeffs:
            parts.append(c.to_bytes())
        return b''.join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Polynomial':
        """Deserialize polynomial."""
        n = int.from_bytes(data[:4], 'big')
        coeffs = []
        for i in range(n):
            start = 4 + i * 8
            coeffs.append(FieldElement.from_bytes(data[start:start+8]))
        return cls(coeffs)


# =============================================================================
# FFT Operations
# =============================================================================

def fft(values: List[FieldElement], omega: FieldElement) -> List[FieldElement]:
    """
    Fast Fourier Transform over finite field.

    Computes DFT: Y[k] = Σ_{j=0}^{n-1} x[j] * ω^{jk}

    Args:
        values: Input values (length must be power of 2)
        omega: Primitive n-th root of unity

    Returns:
        FFT result (evaluations at [1, ω, ω^2, ..., ω^{n-1}])

    Time complexity: O(n log n)
    """
    n = len(values)
    if n == 1:
        return values[:]

    if n & (n - 1) != 0:
        raise ValueError("Length must be power of 2")

    # Bit-reversal permutation
    result = _bit_reverse_copy(values)

    # Cooley-Tukey iterative FFT
    m = 1
    while m < n:
        wm = omega ** (n // (2 * m))  # Principal 2m-th root
        for k in range(0, n, 2 * m):
            w = FieldElement.one()
            for j in range(m):
                t = w * result[k + j + m]
                u = result[k + j]
                result[k + j] = u + t
                result[k + j + m] = u - t
                w = w * wm
        m *= 2

    return result


def ifft(values: List[FieldElement], omega: FieldElement) -> List[FieldElement]:
    """
    Inverse Fast Fourier Transform.

    Computes inverse DFT: x[j] = (1/n) * Σ_{k=0}^{n-1} Y[k] * ω^{-jk}

    Args:
        values: FFT values (length must be power of 2)
        omega: Primitive n-th root of unity used in forward FFT

    Returns:
        Inverse FFT result (original polynomial coefficients)
    """
    n = len(values)
    omega_inv = omega.inverse()

    # FFT with inverse root
    result = fft(values, omega_inv)

    # Scale by 1/n
    n_inv = FieldElement(n).inverse()
    return [v * n_inv for v in result]


def ifft_to_poly(evaluations: List[FieldElement]) -> Polynomial:
    """
    Convert FFT evaluations to polynomial coefficients.
    """
    n = len(evaluations)
    # Get n-th root of unity
    order = 0
    temp = n
    while temp > 1:
        temp //= 2
        order += 1
    omega = FieldElement.primitive_root_of_unity(order)

    coeffs = ifft(evaluations, omega)
    return Polynomial(coeffs)


def _bit_reverse_copy(values: List[FieldElement]) -> List[FieldElement]:
    """Copy with bit-reversal permutation."""
    n = len(values)
    log_n = (n - 1).bit_length()
    result = [FieldElement.zero()] * n

    for i in range(n):
        j = _bit_reverse(i, log_n)
        result[j] = values[i]

    return result


def _bit_reverse(x: int, bits: int) -> int:
    """Reverse bits of x."""
    result = 0
    for _ in range(bits):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


# =============================================================================
# Low-Degree Extension
# =============================================================================

def low_degree_extend(
    values: List[FieldElement],
    blowup_factor: int
) -> List[FieldElement]:
    """
    Perform low-degree extension (Reed-Solomon encoding).

    Given evaluations on a domain of size n, compute evaluations
    on a larger domain of size n * blowup_factor.

    This is the core of STARK soundness: the extended evaluations
    are consistent with a low-degree polynomial.

    Args:
        values: Evaluations on trace domain
        blowup_factor: Extension factor (typically 4-16)

    Returns:
        Evaluations on extended domain
    """
    n = len(values)
    extended_n = n * blowup_factor

    # Get roots of unity
    trace_order = (n - 1).bit_length()
    if 1 << trace_order != n:
        trace_order += 1
    extended_order = trace_order + (blowup_factor - 1).bit_length()

    omega_trace = FieldElement.primitive_root_of_unity(trace_order)
    omega_extended = FieldElement.primitive_root_of_unity(extended_order)

    # Interpolate to get polynomial coefficients
    coeffs = ifft(values, omega_trace)

    # Pad with zeros to extended size
    coeffs_extended = coeffs + [FieldElement.zero()] * (extended_n - n)

    # Evaluate on extended domain
    extended_values = fft(coeffs_extended, omega_extended)

    return extended_values


def get_domain(size: int) -> List[FieldElement]:
    """
    Get evaluation domain of given size.

    Returns [1, ω, ω^2, ..., ω^{n-1}] where ω is primitive n-th root.
    """
    order = 0
    temp = size
    while temp > 1:
        temp //= 2
        order += 1

    if (1 << order) != size:
        raise ValueError(f"Size must be power of 2, got {size}")

    omega = FieldElement.primitive_root_of_unity(order)
    domain = [FieldElement.one()]
    for _ in range(size - 1):
        domain.append(domain[-1] * omega)

    return domain
