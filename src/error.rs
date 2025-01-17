use andromeda_std::error::ContractError as AndromedaContractError;
use cosmwasm_std::StdError;
use cw_utils::ThresholdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("0")]
    ADO(#[from] AndromedaContractError),

    #[error("{0}")]
    Threshold(#[from] ThresholdError),

    #[error("Required weight cannot be zero")]
    ZeroWeight {},

    #[error("Not possible to reach required (passing) weight")]
    UnreachableWeight {},

    #[error("No voters")]
    NoVoters {},

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Proposal is not open")]
    NotOpen {},

    #[error("Proposal voting period has expired")]
    Expired {},

    #[error("Proposal must expire before you can close it")]
    NotExpired {},

    #[error("Wrong expiration option")]
    WrongExpiration {},

    #[error("Already voted on this proposal")]
    AlreadyVoted {},

    #[error("Proposal must have passed and not yet been executed")]
    WrongExecuteStatus {},

    #[error("Cannot close completed or passed proposals")]
    WrongCloseStatus {},
    #[error("Cannot migrate from different contract type: {previous_contract}")]
    CannotMigrate { previous_contract: String },
}

impl Into<AndromedaContractError> for ContractError {
    fn into(self) -> AndromedaContractError {
        match self {
            ContractError::ADO(err) => err,
            _ => panic!("Unsupported error type"),
        }
    }
}
