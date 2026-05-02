//! Scheme-independent linear transformation descriptors.

use std::collections::BTreeSet;

use crate::error::{CircuitsError, Result};

/// Describes the semantic shape of a linear transformation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinearTransformKind {
    /// A dense slot matrix with no additional structural promise.
    Dense,
    /// A cyclic slot permutation by the contained signed offset.
    SlotPermutation(isize),
    /// A diagonal representation already suitable for rotation-based evaluation.
    Diagonal,
}

/// A dense linear transformation over slots.
#[derive(Clone, Debug, PartialEq)]
pub struct LinearTransform<T> {
    kind: LinearTransformKind,
    rows: Vec<Vec<T>>,
}

impl<T> LinearTransform<T> {
    /// Builds a square dense linear transformation.
    pub fn dense(rows: Vec<Vec<T>>) -> Result<Self> {
        validate_square(&rows)?;
        Ok(Self {
            kind: LinearTransformKind::Dense,
            rows,
        })
    }

    /// Builds a cyclic slot permutation descriptor.
    pub fn slot_permutation(slot_count: usize, offset: isize, zero: T, one: T) -> Result<Self>
    where
        T: Clone,
    {
        if slot_count == 0 {
            return Err(CircuitsError::InvalidParameters(
                "slot count must be nonzero",
            ));
        }

        let mut rows = vec![vec![zero; slot_count]; slot_count];
        for out in 0..slot_count {
            let input = wrap_index(out as isize + offset, slot_count);
            rows[out][input] = one.clone();
        }

        Ok(Self {
            kind: LinearTransformKind::SlotPermutation(offset),
            rows,
        })
    }

    /// Returns the transform kind.
    pub fn kind(&self) -> LinearTransformKind {
        self.kind
    }

    /// Returns the number of input/output slots.
    pub fn slot_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns the dense matrix rows.
    pub fn rows(&self) -> &[Vec<T>] {
        &self.rows
    }

    /// Converts this transform to cyclic diagonals.
    pub fn to_diagonal_matrix(&self) -> DiagonalMatrix<T>
    where
        T: Clone + Default + PartialEq,
    {
        DiagonalMatrix::from_linear_transform(self)
    }
}

/// One nonzero cyclic diagonal of a slot matrix.
#[derive(Clone, Debug, PartialEq)]
pub struct Diagonal<T> {
    offset: usize,
    values: Vec<T>,
}

impl<T> Diagonal<T> {
    /// Creates a diagonal at a cyclic offset.
    pub fn new(offset: usize, values: Vec<T>) -> Result<Self> {
        if values.is_empty() {
            return Err(CircuitsError::InvalidParameters(
                "diagonal must be nonempty",
            ));
        }
        Ok(Self {
            offset: offset % values.len(),
            values,
        })
    }

    /// Cyclic diagonal offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Diagonal values in output-slot order.
    pub fn values(&self) -> &[T] {
        &self.values
    }
}

/// Cyclic diagonal representation of a square slot matrix.
#[derive(Clone, Debug, PartialEq)]
pub struct DiagonalMatrix<T> {
    slot_count: usize,
    diagonals: Vec<Diagonal<T>>,
}

impl<T> DiagonalMatrix<T> {
    /// Builds a diagonal matrix from explicit diagonals.
    pub fn new(slot_count: usize, diagonals: Vec<Diagonal<T>>) -> Result<Self> {
        if slot_count == 0 {
            return Err(CircuitsError::InvalidParameters(
                "slot count must be nonzero",
            ));
        }
        if diagonals.iter().any(|diag| diag.values.len() != slot_count) {
            return Err(CircuitsError::DimensionMismatch);
        }

        Ok(Self {
            slot_count,
            diagonals,
        })
    }

    /// Converts a dense transform into nonzero cyclic diagonals.
    pub fn from_linear_transform(transform: &LinearTransform<T>) -> Self
    where
        T: Clone + Default + PartialEq,
    {
        let n = transform.slot_count();
        let zero = T::default();
        let mut diagonals = Vec::new();

        for offset in 0..n {
            let values: Vec<T> = (0..n)
                .map(|row| transform.rows[row][(row + offset) % n].clone())
                .collect();
            if values.iter().any(|value| value != &zero) {
                diagonals.push(Diagonal { offset, values });
            }
        }

        Self {
            slot_count: n,
            diagonals,
        }
    }

    /// Number of slots represented by this matrix.
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Nonzero cyclic diagonals.
    pub fn diagonals(&self) -> &[Diagonal<T>] {
        &self.diagonals
    }

    /// Reconstructs the dense matrix rows.
    pub fn to_dense(&self) -> Vec<Vec<T>>
    where
        T: Clone + Default,
    {
        let mut rows = vec![vec![T::default(); self.slot_count]; self.slot_count];
        for diagonal in &self.diagonals {
            for row in 0..self.slot_count {
                rows[row][(row + diagonal.offset) % self.slot_count] = diagonal.values[row].clone();
            }
        }
        rows
    }

    /// Plans baby-step giant-step evaluation for this diagonal matrix.
    pub fn bsgs_plan(&self, baby_step_count: usize) -> Result<BabyStepGiantStepPlan> {
        BabyStepGiantStepPlan::new(
            self.slot_count,
            self.diagonals.iter().map(Diagonal::offset).collect(),
            baby_step_count,
        )
    }
}

/// Rotation schedule for diagonal-method linear transforms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BabyStepGiantStepPlan {
    slot_count: usize,
    baby_step_count: usize,
    diagonal_offsets: Vec<usize>,
    baby_steps: Vec<usize>,
    giant_steps: Vec<usize>,
}

impl BabyStepGiantStepPlan {
    /// Builds a BSGS plan from diagonal offsets.
    pub fn new(
        slot_count: usize,
        diagonal_offsets: Vec<usize>,
        baby_step_count: usize,
    ) -> Result<Self> {
        if slot_count == 0 {
            return Err(CircuitsError::InvalidParameters(
                "slot count must be nonzero",
            ));
        }
        if baby_step_count == 0 {
            return Err(CircuitsError::InvalidParameters(
                "baby step count must be nonzero",
            ));
        }

        let mut normalized: Vec<usize> = diagonal_offsets
            .into_iter()
            .map(|offset| offset % slot_count)
            .collect();
        normalized.sort_unstable();
        normalized.dedup();

        let mut baby_steps = BTreeSet::new();
        let mut giant_steps = BTreeSet::new();
        for offset in &normalized {
            baby_steps.insert(offset % baby_step_count);
            giant_steps.insert((offset / baby_step_count) * baby_step_count % slot_count);
        }

        Ok(Self {
            slot_count,
            baby_step_count,
            diagonal_offsets: normalized,
            baby_steps: baby_steps.into_iter().collect(),
            giant_steps: giant_steps.into_iter().collect(),
        })
    }

    /// Number of slots in the transform.
    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Configured baby-step group size.
    pub fn baby_step_count(&self) -> usize {
        self.baby_step_count
    }

    /// Normalized diagonal offsets covered by this plan.
    pub fn diagonal_offsets(&self) -> &[usize] {
        &self.diagonal_offsets
    }

    /// Baby rotations needed by the plan.
    pub fn baby_steps(&self) -> &[usize] {
        &self.baby_steps
    }

    /// Giant rotations needed by the plan.
    pub fn giant_steps(&self) -> &[usize] {
        &self.giant_steps
    }

    /// Returns `(giant_step, baby_step)` for a covered diagonal offset.
    pub fn decompose_offset(&self, offset: usize) -> Option<(usize, usize)> {
        let offset = offset % self.slot_count;
        self.diagonal_offsets.binary_search(&offset).ok().map(|_| {
            (
                (offset / self.baby_step_count) * self.baby_step_count % self.slot_count,
                offset % self.baby_step_count,
            )
        })
    }
}

fn validate_square<T>(rows: &[Vec<T>]) -> Result<()> {
    if rows.is_empty() {
        return Err(CircuitsError::InvalidParameters("matrix must be nonempty"));
    }
    if rows.iter().any(|row| row.len() != rows.len()) {
        return Err(CircuitsError::DimensionMismatch);
    }
    Ok(())
}

fn wrap_index(index: isize, modulus: usize) -> usize {
    index.rem_euclid(modulus as isize) as usize
}
