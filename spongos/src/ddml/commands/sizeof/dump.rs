use crate::{
    ddml::commands::{sizeof::Context, Dump},
    error::Result,
};

/// Displays context size
impl Dump for Context {
    fn dump(&mut self, args: core::fmt::Arguments) -> Result<&mut Self> {
        println!("{}: size=[{}]", args, self.size);
        Ok(self)
    }
}
