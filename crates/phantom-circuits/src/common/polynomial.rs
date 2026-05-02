//! Scheme-independent polynomial evaluation planning.

use crate::error::{CircuitsError, Result};

/// Strategy chosen for a polynomial evaluation plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolynomialEvalStrategy {
    /// Constant polynomial; no ciphertext multiplications are needed.
    Constant,
    /// Horner evaluation.
    Horner,
    /// Power-basis evaluation using all powers up to the degree.
    PowerBasis,
    /// Paterson-Stockmeyer baby-step giant-step evaluation.
    PatersonStockmeyer,
}

/// A plan for evaluating a polynomial of known degree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolynomialEvalPlan {
    degree: usize,
    coefficient_count: usize,
    strategy: PolynomialEvalStrategy,
    power_basis: PowerBasisPlan,
    paterson_stockmeyer: Option<PatersonStockmeyerPlan>,
}

impl PolynomialEvalPlan {
    /// Chooses a default strategy for a coefficient vector.
    pub fn for_coefficients<T>(coefficients: &[T]) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(CircuitsError::EmptyPolynomial);
        }
        Self::for_degree(coefficients.len() - 1)
    }

    /// Chooses a default strategy for a degree.
    pub fn for_degree(degree: usize) -> Result<Self> {
        let strategy = if degree == 0 {
            PolynomialEvalStrategy::Constant
        } else if degree <= 3 {
            PolynomialEvalStrategy::Horner
        } else if degree <= 7 {
            PolynomialEvalStrategy::PowerBasis
        } else {
            PolynomialEvalStrategy::PatersonStockmeyer
        };
        Self::with_strategy(degree, strategy)
    }

    /// Builds a plan with an explicit strategy.
    pub fn with_strategy(degree: usize, strategy: PolynomialEvalStrategy) -> Result<Self> {
        let power_basis = PowerBasisPlan::new(degree)?;
        let paterson_stockmeyer = match strategy {
            PolynomialEvalStrategy::PatersonStockmeyer => {
                Some(PatersonStockmeyerPlan::new(degree, None)?)
            }
            _ => None,
        };

        Ok(Self {
            degree,
            coefficient_count: degree + 1,
            strategy,
            power_basis,
            paterson_stockmeyer,
        })
    }

    /// Polynomial degree covered by this plan.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Number of coefficients expected by this plan.
    pub fn coefficient_count(&self) -> usize {
        self.coefficient_count
    }

    /// Chosen strategy.
    pub fn strategy(&self) -> PolynomialEvalStrategy {
        self.strategy
    }

    /// Required powers for straightforward power-basis-style evaluation.
    pub fn power_basis(&self) -> &PowerBasisPlan {
        &self.power_basis
    }

    /// Paterson-Stockmeyer plan when that strategy was selected.
    pub fn paterson_stockmeyer(&self) -> Option<&PatersonStockmeyerPlan> {
        self.paterson_stockmeyer.as_ref()
    }
}

/// Required monomial powers for a direct power basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowerBasisPlan {
    degree: usize,
    powers: Vec<usize>,
}

impl PowerBasisPlan {
    /// Builds a power basis plan through `degree`.
    pub fn new(degree: usize) -> Result<Self> {
        let powers = (1..=degree).collect();
        Ok(Self { degree, powers })
    }

    /// Maximum degree covered by this plan.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Nonconstant powers that must be available.
    pub fn powers(&self) -> &[usize] {
        &self.powers
    }
}

/// Baby-step giant-step plan for Paterson-Stockmeyer polynomial evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatersonStockmeyerPlan {
    degree: usize,
    baby_step_count: usize,
    giant_step_count: usize,
    baby_powers: Vec<usize>,
    giant_powers: Vec<usize>,
    blocks: Vec<PolynomialBlock>,
}

impl PatersonStockmeyerPlan {
    /// Builds a Paterson-Stockmeyer plan.
    pub fn new(degree: usize, baby_step_count: Option<usize>) -> Result<Self> {
        if degree == 0 {
            return Err(CircuitsError::InvalidParameters(
                "Paterson-Stockmeyer requires positive degree",
            ));
        }

        let baby_step_count = baby_step_count.unwrap_or_else(|| integer_sqrt_ceil(degree + 1));
        if baby_step_count == 0 {
            return Err(CircuitsError::InvalidParameters(
                "baby step count must be nonzero",
            ));
        }

        let giant_step_count = degree / baby_step_count;
        let baby_limit = baby_step_count.min(degree);
        let baby_powers = (1..=baby_limit).collect();
        let giant_powers = (1..=giant_step_count)
            .map(|giant| giant * baby_step_count)
            .collect();

        let mut blocks = Vec::new();
        let mut start = 0;
        while start <= degree {
            let end = (start + baby_step_count - 1).min(degree);
            blocks.push(PolynomialBlock {
                start_degree: start,
                end_degree: end,
                giant_index: start / baby_step_count,
            });
            start += baby_step_count;
        }

        Ok(Self {
            degree,
            baby_step_count,
            giant_step_count,
            baby_powers,
            giant_powers,
            blocks,
        })
    }

    /// Polynomial degree covered by this plan.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Number of coefficients in each baby block, except possibly the final block.
    pub fn baby_step_count(&self) -> usize {
        self.baby_step_count
    }

    /// Highest giant index needed.
    pub fn giant_step_count(&self) -> usize {
        self.giant_step_count
    }

    /// Powers within a baby block that must be available.
    pub fn baby_powers(&self) -> &[usize] {
        &self.baby_powers
    }

    /// Giant powers that must be available.
    pub fn giant_powers(&self) -> &[usize] {
        &self.giant_powers
    }

    /// Coefficient blocks in ascending degree order.
    pub fn blocks(&self) -> &[PolynomialBlock] {
        &self.blocks
    }
}

/// One coefficient block in a Paterson-Stockmeyer plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolynomialBlock {
    start_degree: usize,
    end_degree: usize,
    giant_index: usize,
}

impl PolynomialBlock {
    /// First coefficient degree in the block.
    pub fn start_degree(&self) -> usize {
        self.start_degree
    }

    /// Last coefficient degree in the block.
    pub fn end_degree(&self) -> usize {
        self.end_degree
    }

    /// Multiplier index for the giant-step power.
    pub fn giant_index(&self) -> usize {
        self.giant_index
    }
}

fn integer_sqrt_ceil(value: usize) -> usize {
    if value <= 1 {
        return value;
    }

    let mut root = 1usize;
    while root.saturating_mul(root) < value {
        root += 1;
    }
    root
}
