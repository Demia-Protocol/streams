use core::iter;

use crate::{
    ddml::commands::{sizeof::Context, Repeated},
    error::Result,
};

/// Repeated modifier. The actual number of repetitions must be wrapped
/// (absorbed/masked/skipped) explicitly.
impl<I, C> Repeated<I, C> for Context
where
    I: iter::Iterator,
    C: for<'a> FnMut(&'a mut Self, I::Item) -> Result<&'a mut Self>,
{
    fn repeated(&mut self, mut values_iter: I, value_handle: C) -> Result<&mut Self> {
        values_iter.try_fold(self, value_handle)
    }
}
