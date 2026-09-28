// Copyright 2024 Stellar-K8s Contributors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cross-chain bridge relayer verification contract.
//!
//! See [`lib`] for the full design and [`nonce`] for replay-protection details.

pub mod lib;
pub mod nonce;

pub use lib::{
    BridgeError, BridgeRelayerContract, CrossChainMessage, ExecutionDispatcher, NoopDispatcher,
    RecordingDispatcher, RelayerKey, RelayerSignature,
};
pub use nonce::{NonceError, NonceKey, NonceStore};
