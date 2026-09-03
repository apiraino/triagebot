// #[derive(PartialEq, Eq, Debug)]
// pub struct ApproveCommand;

// use crate::error::Error;
// use crate::token::{Token, Tokenizer};

// impl ApproveCommand {
//     pub fn parse<'a>(input: &mut Tokenizer<'a>) -> Result<Option<Self>, Error<'a>> {
//         if let Some(Token::Word("prioritize")) = input.peek_token()? {
//             Ok(Some(Self))
//         } else {
//             Ok(None)
//         }
//     }
// }

use crate::{
    config::PrApprovedConfig,
    github::{self, Event},
    handlers::Context,
};
use parser::command::approve::ApproveCommand;

pub(super) async fn handle_command(
    ctx: &Context,
    config: &PrApprovedConfig,
    event: &Event,
    _: ApproveCommand,
) -> anyhow::Result<()> {
    // let labels = vec![github::Label { name: String }];
    // event
    //     .issue()
    //     .unwrap()
    //     .add_labels(&ctx.github, labels)
    //     .await?;
    Ok(())
}
