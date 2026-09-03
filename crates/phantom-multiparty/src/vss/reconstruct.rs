//! Lagrange interpolation: combining `>= threshold` participants' own final
//! combined shares (see [`super::ShareAccumulator::finalize`]) back into the
//! collective secret's own small centered-integer coefficients - without
//! any single party ever holding, or needing to hold, more than their own
//! share.

use curve25519_dalek::scalar::Scalar;

use super::scalar_embed::recover_centered;
use crate::common::ParticipantId;
use crate::{MultipartyError, Result};

/// Computes the Lagrange coefficient for `evaluation_points[index]`,
/// evaluated at `x = 0`: `prod_{j != index} (-x_j) / (x_index - x_j)`.
pub fn lagrange_coefficient_at_zero(index: usize, evaluation_points: &[Scalar]) -> Result<Scalar> {
    let xi = *evaluation_points
        .get(index)
        .ok_or(MultipartyError::InvalidParameters(
            "lagrange_coefficient_at_zero: index out of range",
        ))?;
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for (j, &xj) in evaluation_points.iter().enumerate() {
        if j == index {
            continue;
        }
        numerator *= -xj;
        let diff = xi - xj;
        if diff == Scalar::ZERO {
            return Err(MultipartyError::DuplicateParticipant);
        }
        denominator *= diff;
    }
    Ok(numerator * denominator.invert())
}

/// Reconstructs the collective secret's own `N` small centered-integer
/// coefficients from `>= threshold` participants' own final combined
/// shares (`ParticipantId`, `Y_i` pairs - see
/// [`super::ShareAccumulator::finalize`], discarding its own blinding
/// component: reconstructing the *secret* only ever needs the value
/// vectors, not the blinding scalars, which existed purely to make the
/// intermediate commitments hiding).
///
/// `magnitude_bound` must bound the true reconstructed value's own
/// magnitude (typically `dealer_count * per_dealer_secret_bound` - see
/// [`super::scalar_embed::recover_centered`]'s own doc comment for why this
/// bounded-search approach is sound here specifically). Errs with
/// [`MultipartyError::ThresholdNotMet`] if fewer than `threshold` shares are
/// given - reconstructing from too few shares wouldn't fail loudly on its
/// own (Lagrange interpolation is well-defined for any nonempty point set,
/// it would just silently interpolate the wrong, lower-degree function), so
/// this is an explicit, load-bearing check, not a redundant one.
pub fn reconstruct_secret(
    shares: &[(ParticipantId, Vec<Scalar>)],
    threshold: usize,
    magnitude_bound: i128,
) -> Result<Vec<i128>> {
    if shares.len() < threshold {
        return Err(MultipartyError::ThresholdNotMet);
    }
    let vector_len = shares.first().ok_or(MultipartyError::MissingShare)?.1.len();
    if shares.iter().any(|(_, values)| values.len() != vector_len) {
        return Err(MultipartyError::InvalidParameters(
            "reconstruct_secret: mismatched vector lengths across shares",
        ));
    }

    let evaluation_points: Vec<Scalar> = shares
        .iter()
        .map(|(participant, _)| Scalar::from(participant.get()))
        .collect();
    let coefficients: Vec<Scalar> = (0..shares.len())
        .map(|index| lagrange_coefficient_at_zero(index, &evaluation_points))
        .collect::<Result<_>>()?;

    let mut result = vec![Scalar::ZERO; vector_len];
    for ((_, values), &coefficient) in shares.iter().zip(&coefficients) {
        for (accumulated, value) in result.iter_mut().zip(values) {
            *accumulated += coefficient * value;
        }
    }

    result
        .into_iter()
        .map(|scalar| recover_centered(scalar, magnitude_bound))
        .collect()
}
