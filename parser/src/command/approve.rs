#[derive(PartialEq, Eq, Debug)]
pub struct ApproveCommand;

use crate::error::Error;
use crate::token::{Token, Tokenizer};

impl ApproveCommand {
    pub fn parse<'a>(input: &mut Tokenizer<'a>) -> Result<Option<Self>, Error<'a>> {
        if let Some(Token::Word("approve")) = input.peek_token()? {
            Ok(Some(Self))
        } else {
            Ok(None)
        }
    }
}
