// Copyright 2017-2018 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

//! Primitives for the runtime modules.

use rstd::prelude::*;
use rstd::{self, result, marker::PhantomData};
use runtime_io;
#[cfg(feature = "std")] use std::fmt::{Debug, Display};
#[cfg(feature = "std")] use serde::{Serialize, de::DeserializeOwned};
use substrate_primitives;
use substrate_primitives::Blake2Hasher;
use codec::{Codec, Encode, HasCompact};
pub use integer_sqrt::IntegerSquareRoot;
pub use num_traits::{Zero, One, Bounded};
pub use num_traits::ops::checked::{
	CheckedAdd, CheckedSub, CheckedMul, CheckedDiv, CheckedShl, CheckedShr,
};
use rstd::ops::{
	Add, Sub, Mul, Div, Rem, AddAssign, SubAssign, MulAssign, DivAssign,
	RemAssign, Shl, Shr
};

/// A lazy value.
pub trait Lazy<T: ?Sized> {
	/// Get a reference to the underlying value.
	///
	/// This will compute the value if the function is invoked for the first time.
	fn get(&mut self) -> &T;
}

impl<'a> Lazy<[u8]> for &'a [u8] {
	fn get(&mut self) -> &[u8] { &**self }
}

/// Means of signature verification.
pub trait Verify {
	/// Type of the signer.
	type Signer;
	/// Verify a signature. Return `true` if signature is valid for the value.
	fn verify<L: Lazy<[u8]>>(&self, msg: L, signer: &Self::Signer) -> bool;
}

/// Some sort of check on the origin is performed by this object.
pub trait EnsureOrigin<OuterOrigin> {
	/// A return type.
	type Success;
	/// Perform the origin check.
	fn ensure_origin(o: OuterOrigin) -> result::Result<Self::Success, &'static str>;
}

/// Means of changing one type into another in a manner dependent on the source type.
pub trait Lookup {
	/// Type to lookup from.
	type Source;
	/// Type to lookup into.
	type Target;
	/// Attempt a lookup.
	fn lookup(&self, s: Self::Source) -> result::Result<Self::Target, &'static str>;
}

/// Means of changing one type into another in a manner dependent on the source type.
/// This variant is different to `Lookup` in that it doesn't (can cannot) require any
/// context.
pub trait StaticLookup {
	/// Type to lookup from.
	type Source: Codec + Clone + PartialEq + MaybeDebug;
	/// Type to lookup into.
	type Target;
	/// Attempt a lookup.
	fn lookup(s: Self::Source) -> result::Result<Self::Target, &'static str>;
}

/// A lookup implementation returning the input value.
#[derive(Default)]
pub struct IdentityLookup<T>(PhantomData<T>);
impl<T: Codec + Clone + PartialEq + MaybeDebug> StaticLookup for IdentityLookup<T> {
	type Source = T;
	type Target = T;
	fn lookup(x: T) -> result::Result<T, &'static str> { Ok(x) }
}
impl<T> Lookup for IdentityLookup<T> {
	type Source = T;
	type Target = T;
	fn lookup(&self, x: T) -> result::Result<T, &'static str> { Ok(x) }
}

/// Get the "current" block number.
pub trait CurrentHeight {
	/// The type of the block number.
	type BlockNumber;

	/// Return the current block number. Not allowed to fail.
	fn current_height(&self) -> Self::BlockNumber;
}

/// Translate a block number into a hash.
pub trait BlockNumberToHash {
	/// The type of the block number.
	type BlockNumber: Zero;

	/// The type of the hash.
	type Hash: Encode;

	/// Get the hash for a given block number, or `None` if unknown.
	fn block_number_to_hash(&self, n: Self::BlockNumber) -> Option<Self::Hash>;

	/// Get the genesis block hash; this should always be known.
	fn genesis_hash(&self) -> Self::Hash {
		self.block_number_to_hash(Zero::zero()).expect("All blockchains must know their genesis block hash; qed")
	}
}

/// The account with the given id was killed.
pub trait OnFreeBalanceZero<AccountId> {
	/// The account was the given id was killed.
	fn on_free_balance_zero(who: &AccountId);
}

impl<AccountId> OnFreeBalanceZero<AccountId> for () {
	fn on_free_balance_zero(_who: &AccountId) {}
}
impl<
	AccountId,
	X: OnFreeBalanceZero<AccountId>,
	Y: OnFreeBalanceZero<AccountId>,
> OnFreeBalanceZero<AccountId> for (X, Y) {
	fn on_free_balance_zero(who: &AccountId) {
		X::on_free_balance_zero(who);
		Y::on_free_balance_zero(who);
	}
}

/// Trait for a hook to get called when some balance has been minted, causing dilution.
pub trait OnDilution<Balance> {
	/// Some `portion` of the total balance just "grew" by `minted`. `portion` is the pre-growth
	/// amount (it doesn't take account of the recent growth).
	fn on_dilution(minted: Balance, portion: Balance);
}

impl<Balance> OnDilution<Balance> for () {
	fn on_dilution(_minted: Balance, _portion: Balance) {}
}

/// Determinator for whether a given account is able to transfer balance.
pub trait EnsureAccountLiquid<AccountId> {
	/// Returns `Ok` iff the account is able to transfer funds normally. `Err(...)`
	/// with the reason why not otherwise.
	fn ensure_account_liquid(who: &AccountId) -> result::Result<(), &'static str>;
}
impl<
	AccountId,
	X: EnsureAccountLiquid<AccountId>,
	Y: EnsureAccountLiquid<AccountId>,
> EnsureAccountLiquid<AccountId> for (X, Y) {
	fn ensure_account_liquid(who: &AccountId) -> result::Result<(), &'static str> {
		X::ensure_account_liquid(who)?;
		Y::ensure_account_liquid(who)
	}
}
impl<AccountId> EnsureAccountLiquid<AccountId> for () {
	fn ensure_account_liquid(_who: &AccountId) -> result::Result<(), &'static str> { Ok(()) }
}

/// Outcome of a balance update.
pub enum UpdateBalanceOutcome {
	/// Account balance was simply updated.
	Updated,
	/// The update has led to killing of the account.
	AccountKilled,
}

/// Abstraction over staking mecanism
pub trait Staking<AccountId> {
	/// The balance of an account.
	type Balance: SimpleArithmetic + As<usize> + As<u64> + Codec + Copy + MaybeSerializeDebug + Default;

	// PUBLIC IMMUTABLES

	/// The combined balance of `who`.
	fn total_balance(who: &AccountId) -> Self::Balance;

	/// Some result as `slash(who, value)` (but without the side-effects) assuming there are no
	/// balance changes in the meantime and only the reserved balance is not taken into account.
	fn can_slash(who: &AccountId, value: Self::Balance) -> bool;

	/// Same result as `reserve(who, value)` (but without the side-effects) assuming there
	/// are no balance changes in the meantime.
	fn can_reserve(who: &AccountId, value: Self::Balance) -> bool;

	/// The total amount of stake on the system.
	fn total_issuance() -> Self:: Balance;

	/// The 'free' balance of a given account.
	///
	/// This is the only balance that matters in terms of most operations on tokens. It is
	/// alone used to determine the balance when in the contract execution environment. When this
	/// balance falls below the value of `ExistentialDeposit`, then the 'current account' is
	/// deleted: specifically `FreeBalance`. Furthermore, `OnFreeBalanceZero` callback
	/// is invoked, giving a chance to external modules to cleanup data associated with
	/// the deleted account.
	///
	/// `system::AccountNonce` is also deleted if `ReservedBalance` is also zero (it also gets
	/// collapsed to zero if it ever becomes less than `ExistentialDeposit`.
	fn free_balance(who: &AccountId) -> Self::Balance;

	/// The amount of the balance of a given account that is externally reserved; this can still get
	/// slashed, but gets slashed last of all.
	///
	/// This balance is a 'reserve' balance that other subsystems use in order to set aside tokens
	/// that are still 'owned' by the account holder, but which are suspendable. (This is different
	/// and wholly unrelated to the `Bondage` system used in the staking module.)
	///
	/// When this balance falls below the value of `ExistentialDeposit`, then this 'reserve account'
	/// is deleted: specifically, `ReservedBalance`.
	///
	/// `system::AccountNonce` is also deleted if `FreeBalance` is also zero (it also gets
	/// collapsed to zero if it ever becomes less than `ExistentialDeposit`.
	fn reserved_balance(who: &AccountId) -> Self::Balance;

	// PUBLIC MUTABLES (DANGEROUS)

	/// Deducts up to `value` from the combined balance of `who`, preferring to deduct from the
	/// free balance. This function cannot fail.
	///
	/// As much funds up to `value` will be deducted as possible. If this is less than `value`,
	/// then `Some(remaining)` will be returned. Full completion is given by `None`.
	fn slash(who: &AccountId, value: Self::Balance) -> Option<Self::Balance>;

	/// Adds up to `value` to the free balance of `who`.
	///
	/// If `who` doesn't exist, nothing is done and an Err returned.
	fn reward(who: &AccountId, value: Self::Balance) -> result::Result<(), &'static str>;

	/// Adds up to `value` to the free balance of `who`.
	///
	/// If `who` doesn't exist, it is created
	///
	/// Returns if the account was successfully updated or update has led to killing of the account.
	fn reward_creating(who: &AccountId, value: Self::Balance) -> UpdateBalanceOutcome;

	/// Adds up to `value` to the free balance of `who`.
	///
	/// If `who` doesn't exist, nothing is done and an Err returned.
	///
	/// NOTE: This assumes that the total stake remains unchanged after this operation.
	fn reward_with_no_stake_increase(who: &AccountId, value: Self::Balance) -> result::Result<(), &'static str>;

	/// Adds up to `value` to the free balance of `who`.
	///
	/// If `who` doesn't exist, it is created
	///
	/// Returns if the account was successfully updated or update has led to killing of the account.
	///
	/// NOTE: This assumes that the total stake remains unchanged after this operation.
	fn reward_with_no_stake_increase_creating(who: &AccountId, value: Self::Balance) -> UpdateBalanceOutcome;

	/// Moves `value` from balance to reserved balance.
	///
	/// If the free balance is lower than `value`, then no funds will be moved and an `Err` will
	/// be returned to notify of this. This is different behaviour to `unreserve`.
	fn reserve(who: &AccountId, value: Self::Balance) -> result::Result<(), &'static str>;

	/// Moves up to `value` from reserved balance to balance. This function cannot fail.
	///
	/// As much funds up to `value` will be deducted as possible. If this is less than `value`,
	/// then `Some(remaining)` will be returned. Full completion is given by `None`.
	/// NOTE: This is different to `reserve`.
	fn unreserve(who: &AccountId, value: Self::Balance) -> Option<Self::Balance>;

	/// Deducts up to `value` from reserved balance of `who`. This function cannot fail.
	///
	/// As much funds up to `value` will be deducted as possible. If this is less than `value`,
	/// then `Some(remaining)` will be returned. Full completion is given by `None`.
	fn slash_reserved(who: &AccountId, value: Self::Balance) -> Option<Self::Balance>;

	/// Moves up to `value` from reserved balance of account `slashed` to free balance of account
	/// `beneficiary`. `beneficiary` must exist for this to succeed. If it does not, `Err` will be
	/// returned.
	///
	/// As much funds up to `value` will be moved as possible. If this is less than `value`, then
	/// `Ok(Some(remaining))` will be returned. Full completion is given by `Ok(None)`.
	fn repatriate_reserved(
		slashed: &AccountId,
		beneficiary: &AccountId,
		value: Self::Balance
	) -> result::Result<Option<Self::Balance>, &'static str>;
}

/// Simple payment making trait, operating on a single generic `AccountId` type.
pub trait MakePayment<AccountId> {
	/// Make some sort of payment concerning `who` for an extrinsic (transaction) of encoded length
	/// `encoded_len` bytes. Return true iff the payment was successful.
	fn make_payment(who: &AccountId, encoded_len: usize) -> Result<(), &'static str>;
}

impl<T> MakePayment<T> for () {
	fn make_payment(_: &T, _: usize) -> Result<(), &'static str> { Ok(()) }
}

/// Extensible conversion trait. Generic over both source and destination types.
pub trait Convert<A, B> {
	/// Make conversion.
	fn convert(a: A) -> B;
}

/// Simple trait similar to `Into`, except that it can be used to convert numerics between each
/// other.
pub trait As<T> {
	/// Convert forward (ala `Into::into`).
	fn as_(self) -> T;
	/// Convert backward (ala `From::from`).
	fn sa(T) -> Self;
}

macro_rules! impl_numerics {
	( $( $t:ty ),* ) => {
		$(
			impl_numerics!($t: u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize,);
		)*
	};
	( $f:ty : $t:ty, $( $rest:ty, )* ) => {
		impl As<$t> for $f {
			fn as_(self) -> $t { self as $t }
			fn sa(t: $t) -> Self { t as Self }
		}
		impl_numerics!($f: $( $rest, )*);
	};
	( $f:ty : ) => {}
}

impl_numerics!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

/// A structure that performs identity conversion.
pub struct Identity;
impl<T> Convert<T, T> for Identity {
	fn convert(a: T) -> T { a }
}
impl<T> Convert<T, ()> for () {
	fn convert(_: T) -> () { () }
}

/// A meta trait for arithmetic.
pub trait SimpleArithmetic:
	Zero + One + IntegerSquareRoot + As<u64> +
	Add<Self, Output = Self> + AddAssign<Self> +
	Sub<Self, Output = Self> + SubAssign<Self> +
	Mul<Self, Output = Self> + MulAssign<Self> +
	Div<Self, Output = Self> + DivAssign<Self> +
	Rem<Self, Output = Self> + RemAssign<Self> +
	Shl<u32, Output = Self> + Shr<u32, Output = Self> +
	CheckedShl +
	CheckedShr +
	CheckedAdd +
	CheckedSub +
	CheckedMul +
	CheckedDiv +
	PartialOrd<Self> + Ord +
	HasCompact
{}
impl<T:
	Zero + One + IntegerSquareRoot + As<u64> +
	Add<Self, Output = Self> + AddAssign<Self> +
	Sub<Self, Output = Self> + SubAssign<Self> +
	Mul<Self, Output = Self> + MulAssign<Self> +
	Div<Self, Output = Self> + DivAssign<Self> +
	Rem<Self, Output = Self> + RemAssign<Self> +
	Shl<u32, Output = Self> + Shr<u32, Output = Self> +
	CheckedShl +
	CheckedShr +
	CheckedAdd +
	CheckedSub +
	CheckedMul +
	CheckedDiv +
	PartialOrd<Self> + Ord +
	HasCompact
> SimpleArithmetic for T {}

/// Trait for things that can be clear (have no bits set). For numeric types, essentially the same
/// as `Zero`.
pub trait Clear {
	/// True iff no bits are set.
	fn is_clear(&self) -> bool;

	/// Return the value of Self that is clear.
	fn clear() -> Self;
}

impl<T: Default + Eq + PartialEq> Clear for T {
	fn is_clear(&self) -> bool { *self == Self::clear() }
	fn clear() -> Self { Default::default() }
}

/// A meta trait for all bit ops.
pub trait SimpleBitOps:
	Sized + Clear +
	rstd::ops::BitOr<Self, Output = Self> +
	rstd::ops::BitXor<Self, Output = Self> +
	rstd::ops::BitAnd<Self, Output = Self>
{}
impl<T:
	Sized + Clear +
	rstd::ops::BitOr<Self, Output = Self> +
	rstd::ops::BitXor<Self, Output = Self> +
	rstd::ops::BitAnd<Self, Output = Self>
> SimpleBitOps for T {}

/// The block finalisation trait. Implementing this lets you express what should happen
/// for your module when the block is ending.
pub trait OnFinalise<BlockNumber> {
	/// The block is being finalised. Implement to have something happen.
	fn on_finalise(_n: BlockNumber) {}
}

impl<N> OnFinalise<N> for () {}

macro_rules! tuple_impl {
	($one:ident,) => {
		impl<Number: Copy, $one: OnFinalise<Number>> OnFinalise<Number> for ($one,) {
			fn on_finalise(n: Number) {
				$one::on_finalise(n);
			}
		}
	};
	($first:ident, $($rest:ident,)+) => {
		impl<
			Number: Copy,
			$first: OnFinalise<Number>,
			$($rest: OnFinalise<Number>),+
		> OnFinalise<Number> for ($first, $($rest),+) {
			fn on_finalise(n: Number) {
				$first::on_finalise(n);
				$($rest::on_finalise(n);)+
			}
		}
		tuple_impl!($($rest,)+);
	}
}

#[allow(non_snake_case)]
tuple_impl!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,);

/// Abstraction around hashing
pub trait Hash: 'static + MaybeSerializeDebug + Clone + Eq + PartialEq {	// Stupid bug in the Rust compiler believes derived
																	// traits must be fulfilled by all type parameters.
	/// The hash type produced.
	type Output: Member + MaybeSerializeDebug + AsRef<[u8]> + AsMut<[u8]>;

	/// Produce the hash of some byte-slice.
	fn hash(s: &[u8]) -> Self::Output;

	/// Produce the hash of some codec-encodable value.
	fn hash_of<S: Codec>(s: &S) -> Self::Output {
		Encode::using_encoded(s, Self::hash)
	}

	/// Produce the trie-db root of a mapping from indices to byte slices.
	fn enumerated_trie_root(items: &[&[u8]]) -> Self::Output;

	/// Iterator-based version of `enumerated_trie_root`.
	fn ordered_trie_root<
		I: IntoIterator<Item = A> + Iterator<Item = A>,
		A: AsRef<[u8]>
	>(input: I) -> Self::Output;

	/// The Patricia tree root of the given mapping as an iterator.
	fn trie_root<
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>
	>(input: I) -> Self::Output;

	/// Acquire the global storage root.
	fn storage_root() -> Self::Output;

	/// Acquire the global storage changes root.
	fn storage_changes_root(parent_hash: Self::Output, parent_number: u64) -> Option<Self::Output>;
}

/// Blake2-256 Hash implementation.
#[derive(PartialEq, Eq, Clone)]
#[cfg_attr(feature = "std", derive(Debug, Serialize, Deserialize))]
pub struct BlakeTwo256;

impl Hash for BlakeTwo256 {
	type Output = substrate_primitives::H256;
	fn hash(s: &[u8]) -> Self::Output {
		runtime_io::blake2_256(s).into()
	}
	fn enumerated_trie_root(items: &[&[u8]]) -> Self::Output {
		runtime_io::enumerated_trie_root::<Blake2Hasher>(items).into()
	}
	fn trie_root<
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>
	>(input: I) -> Self::Output {
		runtime_io::trie_root::<Blake2Hasher, _, _, _>(input).into()
	}
	fn ordered_trie_root<
		I: IntoIterator<Item = A> + Iterator<Item = A>,
		A: AsRef<[u8]>
	>(input: I) -> Self::Output {
		runtime_io::ordered_trie_root::<Blake2Hasher, _, _>(input).into()
	}
	fn storage_root() -> Self::Output {
		runtime_io::storage_root().into()
	}
	fn storage_changes_root(parent_hash: Self::Output, parent_number: u64) -> Option<Self::Output> {
		runtime_io::storage_changes_root(parent_hash.into(), parent_number).map(Into::into)
	}
}

/// Something that can be checked for equality and printed out to a debug channel if bad.
pub trait CheckEqual {
	/// Perform the equality check.
	fn check_equal(&self, other: &Self);
}

impl CheckEqual for substrate_primitives::H256 {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		use substrate_primitives::hexdisplay::HexDisplay;
		if self != other {
			println!("Hash: given={}, expected={}", HexDisplay::from(self.as_fixed_bytes()), HexDisplay::from(other.as_fixed_bytes()));
		}
	}

	#[cfg(not(feature = "std"))]
	fn check_equal(&self, other: &Self) {
		if self != other {
			runtime_io::print("Hash not equal");
			runtime_io::print(self.as_bytes());
			runtime_io::print(other.as_bytes());
		}
	}
}

impl<I> CheckEqual for I where I: DigestItem {
	#[cfg(feature = "std")]
	fn check_equal(&self, other: &Self) {
		if self != other {
			println!("DigestItem: given={:?}, expected={:?}", self, other);
		}
	}

	#[cfg(not(feature = "std"))]
	fn check_equal(&self, other: &Self) {
		if self != other {
			runtime_io::print("DigestItem not equal");
			runtime_io::print(&Encode::encode(self)[..]);
			runtime_io::print(&Encode::encode(other)[..]);
		}
	}
}

/// A type that implements Serialize and Debug when in std environment.
#[cfg(feature = "std")]
pub trait MaybeSerializeDebugButNotDeserialize: Serialize + Debug {}
#[cfg(feature = "std")]
impl<T: Serialize + Debug> MaybeSerializeDebugButNotDeserialize for T {}

/// A type that implements Serialize and Debug when in std environment.
#[cfg(not(feature = "std"))]
pub trait MaybeSerializeDebugButNotDeserialize {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSerializeDebugButNotDeserialize for T {}

/// A type that implements Serialize when in std environment.
#[cfg(feature = "std")]
pub trait MaybeSerialize: Serialize {}
#[cfg(feature = "std")]
impl<T: Serialize> MaybeSerialize for T {}

/// A type that implements Serialize when in std environment.
#[cfg(not(feature = "std"))]
pub trait MaybeSerialize {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSerialize for T {}

/// A type that implements Serialize, DeserializeOwned and Debug when in std environment.
#[cfg(feature = "std")]
pub trait MaybeSerializeDebug: Serialize + DeserializeOwned + Debug {}
#[cfg(feature = "std")]
impl<T: Serialize + DeserializeOwned + Debug> MaybeSerializeDebug for T {}

/// A type that implements Serialize, DeserializeOwned and Debug when in std environment.
#[cfg(not(feature = "std"))]
pub trait MaybeSerializeDebug {}
#[cfg(not(feature = "std"))]
impl<T> MaybeSerializeDebug for T {}

/// A type that implements Debug when in std environment.
#[cfg(feature = "std")]
pub trait MaybeDebug: Debug {}
#[cfg(feature = "std")]
impl<T: Debug> MaybeDebug for T {}

/// A type that implements Debug when in std environment.
#[cfg(not(feature = "std"))]
pub trait MaybeDebug {}
#[cfg(not(feature = "std"))]
impl<T> MaybeDebug for T {}

/// A type that implements Display when in std environment.
#[cfg(feature = "std")]
pub trait MaybeDisplay: Display {}
#[cfg(feature = "std")]
impl<T: Display> MaybeDisplay for T {}

/// A type that implements Display when in std environment.
#[cfg(not(feature = "std"))]
pub trait MaybeDisplay {}
#[cfg(not(feature = "std"))]
impl<T> MaybeDisplay for T {}

/// A type that implements Hash when in std environment.
#[cfg(feature = "std")]
pub trait MaybeHash: ::rstd::hash::Hash {}
#[cfg(feature = "std")]
impl<T: ::rstd::hash::Hash> MaybeHash for T {}

/// A type that implements Hash when in std environment.
#[cfg(not(feature = "std"))]
pub trait MaybeHash {}
#[cfg(not(feature = "std"))]
impl<T> MaybeHash for T {}

/// A type that can be used in runtime structures.
pub trait Member: Send + Sync + Sized + MaybeDebug + Eq + PartialEq + Clone + 'static {}
impl<T: Send + Sync + Sized + MaybeDebug + Eq + PartialEq + Clone + 'static> Member for T {}

/// Something which fulfills the abstract idea of a Substrate header. It has types for a `Number`,
/// a `Hash` and a `Digest`. It provides access to an `extrinsics_root`, `state_root` and
/// `parent_hash`, as well as a `digest` and a block `number`.
///
/// You can also create a `new` one from those fields.
pub trait Header: Clone + Send + Sync + Codec + Eq + MaybeSerializeDebugButNotDeserialize + 'static {
	/// Header number.
	type Number: Member + MaybeSerializeDebug + ::rstd::hash::Hash + Copy + MaybeDisplay + SimpleArithmetic + Codec;
	/// Header hash type
	type Hash: Member + MaybeSerializeDebug + ::rstd::hash::Hash + Copy + MaybeDisplay + Default + SimpleBitOps + Codec + AsRef<[u8]> + AsMut<[u8]>;
	/// Hashing algorithm
	type Hashing: Hash<Output = Self::Hash>;
	/// Digest type
	type Digest: Digest<Hash = Self::Hash> + Codec;

	/// Creates new header.
	fn new(
		number: Self::Number,
		extrinsics_root: Self::Hash,
		state_root: Self::Hash,
		parent_hash: Self::Hash,
		digest: Self::Digest
	) -> Self;

	/// Returns a reference to the header number.
	fn number(&self) -> &Self::Number;
	/// Sets the header number.
	fn set_number(&mut self, Self::Number);

	/// Returns a reference to the extrinsics root.
	fn extrinsics_root(&self) -> &Self::Hash;
	/// Sets the extrinsic root.
	fn set_extrinsics_root(&mut self, Self::Hash);

	/// Returns a reference to the state root.
	fn state_root(&self) -> &Self::Hash;
	/// Sets the state root.
	fn set_state_root(&mut self, Self::Hash);

	/// Returns a reference to the parent hash.
	fn parent_hash(&self) -> &Self::Hash;
	/// Sets the parent hash.
	fn set_parent_hash(&mut self, Self::Hash);

	/// Returns a reference to the digest.
	fn digest(&self) -> &Self::Digest;
	/// Get a mutable reference to the digest.
	fn digest_mut(&mut self) -> &mut Self::Digest;
	/// Sets the digest.
	fn set_digest(&mut self, Self::Digest);

	/// Returns the hash of the header.
	fn hash(&self) -> Self::Hash {
		<Self::Hashing as Hash>::hash_of(self)
	}
}

/// Something which fulfills the abstract idea of a Substrate block. It has types for an
/// `Extrinsic` piece of information as well as a `Header`.
///
/// You can get an iterator over each of the `extrinsics` and retrieve the `header`.
pub trait Block: Clone + Send + Sync + Codec + Eq + MaybeSerializeDebugButNotDeserialize + 'static {
	/// Type of extrinsics.
	type Extrinsic: Member + Codec + Extrinsic + MaybeSerialize;
	/// Header type.
	type Header: Header<Hash=Self::Hash>;
	/// Block hash type.
	type Hash: Member + MaybeSerializeDebug + ::rstd::hash::Hash + Copy + MaybeDisplay + Default + SimpleBitOps + Codec + AsRef<[u8]> + AsMut<[u8]>;

	/// Returns a reference to the header.
	fn header(&self) -> &Self::Header;
	/// Returns a reference to the list of extrinsics.
	fn extrinsics(&self) -> &[Self::Extrinsic];
	/// Split the block into header and list of extrinsics.
	fn deconstruct(self) -> (Self::Header, Vec<Self::Extrinsic>);
	/// Creates new block from header and extrinsics.
	fn new(header: Self::Header, extrinsics: Vec<Self::Extrinsic>) -> Self;
	/// Returns the hash of the block.
	fn hash(&self) -> Self::Hash {
		<<Self::Header as Header>::Hashing as Hash>::hash_of(self.header())
	}
}

/// Something that acts like an `Extrinsic`.
pub trait Extrinsic {
	/// Is this `Extrinsic` signed?
	/// If no information are available about signed/unsigned, `None` should be returned.
	fn is_signed(&self) -> Option<bool> { None }
}

/// Extract the hashing type for a block.
pub type HashFor<B> = <<B as Block>::Header as Header>::Hashing;
/// Extract the number type for a block.
pub type NumberFor<B> = <<B as Block>::Header as Header>::Number;
/// Extract the digest type for a block.
pub type DigestFor<B> = <<B as Block>::Header as Header>::Digest;
/// Extract the digest item type for a block.
pub type DigestItemFor<B> = <DigestFor<B> as Digest>::Item;
/// Extract the authority ID type for a block.
pub type AuthorityIdFor<B> = <DigestItemFor<B> as DigestItem>::AuthorityId;

/// A "checkable" piece of information, used by the standard Substrate Executive in order to
/// check the validity of a piece of extrinsic information, usually by verifying the signature.
/// Implement for pieces of information that require some additional context `Context` in order to be
/// checked.
pub trait Checkable<Context>: Sized {
	/// Returned if `check` succeeds.
	type Checked;

	/// Check self, given an instance of Context.
	fn check(self, c: &Context) -> Result<Self::Checked, &'static str>;
}

/// A "checkable" piece of information, used by the standard Substrate Executive in order to
/// check the validity of a piece of extrinsic information, usually by verifying the signature.
/// Implement for pieces of information that don't require additional context in order to be
/// checked.
pub trait BlindCheckable: Sized {
	/// Returned if `check` succeeds.
	type Checked;

	/// Check self.
	fn check(self) -> Result<Self::Checked, &'static str>;
}

// Every `BlindCheckable` is also a `StaticCheckable` for arbitrary `Context`.
impl<T: BlindCheckable, Context> Checkable<Context> for T {
	type Checked = <Self as BlindCheckable>::Checked;
	fn check(self, _c: &Context) -> Result<Self::Checked, &'static str> {
		BlindCheckable::check(self)
	}
}

/// An "executable" piece of information, used by the standard Substrate Executive in order to
/// enact a piece of extrinsic information by marshalling and dispatching to a named function
/// call.
///
/// Also provides information on to whom this information is attributable and an index that allows
/// each piece of attributable information to be disambiguated.
pub trait Applyable: Sized + Send + Sync {
	/// Id of the account that is responsible for this piece of information (sender).
	type AccountId: Member + MaybeDisplay;
	/// Index allowing to disambiguate other `Applyable`s from the same `AccountId`.
	type Index: Member + MaybeDisplay + SimpleArithmetic;
	/// Function call.
	type Call: Member;
	/// Returns a reference to the index if any.
	fn index(&self) -> Option<&Self::Index>;
	/// Returns a reference to the sender if any.
	fn sender(&self) -> Option<&Self::AccountId>;
	/// Deconstructs into function call and sender.
	fn deconstruct(self) -> (Self::Call, Option<Self::AccountId>);
}

/// Something that acts like a `Digest` - it can have `Log`s `push`ed onto it and these `Log`s are
/// each `Codec`.
pub trait Digest: Member + MaybeSerializeDebugButNotDeserialize + Default {
	/// Hash of the items.
	type Hash: Member;
	/// Digest item type.
	type Item: DigestItem<Hash = Self::Hash>;

	/// Get reference to all digest items.
	fn logs(&self) -> &[Self::Item];
	/// Push new digest item.
	fn push(&mut self, item: Self::Item);
	/// Pop a digest item.
	fn pop(&mut self) -> Option<Self::Item>;

	/// Get reference to the first digest item that matches the passed predicate.
	fn log<T: ?Sized, F: Fn(&Self::Item) -> Option<&T>>(&self, predicate: F) -> Option<&T> {
		self.logs().iter()
			.filter_map(predicate)
			.next()
	}
}

/// Single digest item. Could be any type that implements `Member` and provides methods
/// for casting member to 'system' log items, known to substrate.
///
/// If the runtime does not supports some 'system' items, use `()` as a stub.
pub trait DigestItem: Codec + Member + MaybeSerializeDebugButNotDeserialize {
	/// `ChangesTrieRoot` payload.
	type Hash: Member;
	/// `AuthorityChange` payload.
	type AuthorityId: Member + MaybeHash + codec::Encode + codec::Decode;

	/// Returns Some if the entry is the `AuthoritiesChange` entry.
	fn as_authorities_change(&self) -> Option<&[Self::AuthorityId]>;

	/// Returns Some if the entry is the `ChangesTrieRoot` entry.
	fn as_changes_trie_root(&self) -> Option<&Self::Hash>;
}

/// Auxiliary wrapper that holds an api instance and binds it to the given lifetime.
pub struct ApiRef<'a, T>(T, rstd::marker::PhantomData<&'a ()>);

impl<'a, T> From<T> for ApiRef<'a, T> {
	fn from(api: T) -> Self {
		ApiRef(api, Default::default())
	}
}

impl<'a, T> rstd::ops::Deref for ApiRef<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

/// Something that provides a runtime api.
pub trait ProvideRuntimeApi {
	/// The concrete type that provides the api.
	type Api;

	/// Returns the runtime api.
	/// The returned instance will keep track of modifications to the storage. Any successful
	/// call to an api function, will `commit` its changes to an internal buffer. Otherwise,
	/// the modifications will be `discarded`. The modifications will not be applied to the
	/// storage, even on a `commit`.
	fn runtime_api<'a>(&'a self) -> ApiRef<'a, Self::Api>;
}

/// A marker trait for something that knows the type of the runtime block.
pub trait GetRuntimeBlockType {
	/// The `RuntimeBlock` type.
	type RuntimeBlock: self::Block;
}

/// A marker trait for something that knows the type of the node block.
pub trait GetNodeBlockType {
	/// The `NodeBlock` type.
	type NodeBlock: self::Block;
}

/// Something that provides information about a runtime api.
pub trait RuntimeApiInfo {
	/// The identifier of the runtime api.
	const ID: [u8; 8];
	/// The version of the runtime api.
	const VERSION: u32;
}
