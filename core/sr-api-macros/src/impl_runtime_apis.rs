// Copyright 2018 Parity Technologies (UK) Ltd.
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

use utils::{
	unwrap_or_error, generate_crate_access, generate_hidden_includes,
	generate_runtime_mod_name_for_trait, fold_fn_decl_for_client_side, generate_unique_pattern,
	extract_parameter_names_types_and_borrows, generate_native_call_generator_fn_name
};

use proc_macro;
use proc_macro2::{Span, TokenStream};

use quote::quote;

use syn::{
	spanned::Spanned, parse_macro_input, Ident, Type, ItemImpl, MethodSig, Path,
	ImplItem, parse::{Parse, ParseStream, Result, Error}, PathArguments, GenericArgument, TypePath,
	fold::{self, Fold}, FnDecl, parse_quote, FnArg,
};

use std::{collections::HashSet, iter};

/// Unique identifier used to make the hidden includes unique for this macro.
const HIDDEN_INCLUDES_ID: &str = "IMPL_RUNTIME_APIS";

/// The structure used for parsing the runtime api implementations.
struct RuntimeApiImpls {
	impls: Vec<ItemImpl>,
}

impl Parse for RuntimeApiImpls {
	fn parse(input: ParseStream) -> Result<Self> {
		let mut impls = Vec::new();

		while !input.is_empty() {
			impls.push(ItemImpl::parse(input)?);
		}

		Ok(Self { impls })
	}
}

/// Generates the call to the implementation of the requested function.
/// The generated code includes decoding of the input arguments and encoding of the output.
fn generate_impl_call(
	signature: &MethodSig,
	runtime: &Type,
	input: &Ident,
	impl_trait: &Path
) -> Result<TokenStream> {
	let params = extract_parameter_names_types_and_borrows(&signature.decl)?;

	let c = generate_crate_access(HIDDEN_INCLUDES_ID);
	let c_iter = iter::repeat(&c);
	let fn_name = &signature.ident;
	let fn_name_str = iter::repeat(fn_name.to_string());
	let input = iter::repeat(input);
	let pnames = params.iter().map(|v| &v.0);
	let pnames2 = params.iter().map(|v| &v.0);
	let ptypes = params.iter().map(|v| &v.1);
	let pborrow = params.iter().map(|v| &v.2);

	Ok(
		quote!(
			#(
				let #pnames : #ptypes = match #c_iter::runtime_api::Decode::decode(&mut #input) {
					Some(input) => input,
					None => panic!("Bad input data provided to {}", #fn_name_str),
				};
			)*

			let output = <#runtime as #impl_trait>::#fn_name(#( #pborrow #pnames2 ),*);
			#c::runtime_api::Encode::encode(&output)
		).into()
	)
}

/// Extract the trait that is implemented in the given `ItemImpl`.
fn extract_impl_trait<'a>(impl_: &'a ItemImpl) -> Result<&'a Path> {
	impl_.trait_.as_ref().map(|v| &v.1).ok_or_else(
		|| Error::new(impl_.span(), "Only implementation of traits are supported!")
	).and_then(|p| {
		if p.segments.len() > 1 {
			Ok(p)
		} else {
			Err(
				Error::new(
					p.span(),
					"The implemented trait has to be referenced with a path, \
					e.g. `impl client::Core for Runtime`."
				)
			)
		}
	})
}

/// Extracts the runtime block identifier.
fn extract_runtime_block_ident(trait_: &Path) -> Result<&TypePath> {
	let span = trait_.span();
	let segment = trait_
		.segments
		.last()
		.ok_or_else(
			|| Error::new(span, "Empty path not supported")
		)?;
	let generics = segment.value();

	match &generics.arguments {
		PathArguments::AngleBracketed(ref args) => {
			args.args.first().and_then(|v| match v.value() {
			GenericArgument::Type(Type::Path(block)) => Some(block),
				_ => None
			}).ok_or_else(|| Error::new(args.span(), "Missing `Block` generic parameter."))
		},
		PathArguments::None => {
			let span = trait_.segments.last().as_ref().unwrap().value().span();
			Err(Error::new(span, "Missing `Block` generic parameter."))
		},
		PathArguments::Parenthesized(_) => {
			Err(Error::new(generics.arguments.span(), "Unexpected parentheses in path!"))
		}
	}
}

/// Generate all the implementation calls for the given functions.
fn generate_impl_calls(
	impls: &[ItemImpl],
	input: &Ident
) -> Result<Vec<(Ident, Ident, TokenStream)>> {
	let mut impl_calls = Vec::new();

	for impl_ in impls {
		let impl_trait_path = extract_impl_trait(impl_)?;
		let impl_trait = extend_with_runtime_decl_path(impl_trait_path.clone());
		let impl_trait_ident = &impl_trait_path
			.segments
			.last()
			.ok_or_else(|| Error::new(impl_trait_path.span(), "Empty trait path not possible!"))?
			.value()
			.ident;

		for item in &impl_.items {
			match item {
				ImplItem::Method(method) => {
					let impl_call = generate_impl_call(
						&method.sig,
						&impl_.self_ty,
						input,
						&impl_trait
					)?;

					impl_calls.push(
						(impl_trait_ident.clone(), method.sig.ident.clone(), impl_call)
					);
				},
				_ => {},
			}
		}
	}

	Ok(impl_calls)
}

fn prefix_function_with_trait(trait_: &Ident, function: &Ident) -> String {
	format!("{}_{}", trait_.to_string(), function.to_string())
}

/// Generate the dispatch function that is used in native to call into the runtime.
fn generate_dispatch_function(impls: &[ItemImpl]) -> Result<TokenStream> {
	let data = Ident::new("data", Span::call_site());
	let impl_calls = generate_impl_calls(impls, &data)?
		.into_iter()
		.map(|(trait_, fn_name, impl_)| {
			let name = prefix_function_with_trait(&trait_, &fn_name);
			quote!( #name => Some({ #impl_ }), )
		});

	Ok(quote!(
		#[cfg(feature = "std")]
		pub fn dispatch(method: &str, mut #data: &[u8]) -> Option<Vec<u8>> {
			match method {
				#( #impl_calls )*
				_ => None,
			}
		}
	).into())
}

/// Generate the interface functions that are used to call into the runtime in wasm.
fn generate_wasm_interface(impls: &[ItemImpl]) -> Result<TokenStream> {
	let input = Ident::new("input", Span::call_site());
	let c = generate_crate_access(HIDDEN_INCLUDES_ID);
	let impl_calls = generate_impl_calls(impls, &input)?
		.into_iter()
		.map(|(trait_, fn_name, impl_)| {
			let fn_name = Ident::new(
				&prefix_function_with_trait(&trait_, &fn_name),
				Span::call_site()
			);

			quote!(
				#[cfg(not(feature = "std"))]
				#[no_mangle]
				pub fn #fn_name(input_data: *mut u8, input_len: usize) -> u64 {
					let mut #input = if input_len == 0 {
						&[0u8; 0]
					} else {
						unsafe {
							#c::runtime_api::slice::from_raw_parts(input_data, input_len)
						}
					};

					let output = { #impl_ };
					let res = output.as_ptr() as u64 + ((output.len() as u64) << 32);

					// Leak the output vector to avoid it being freed.
					// This is fine in a WASM context since the heap
					// will be discarded after the call.
					#c::runtime_api::mem::forget(output);
					res
				}
			)
		});

	Ok(quote!( #( #impl_calls )* ))
}

fn generate_block_and_block_id_ty(
	runtime: &Type,
	trait_: &'static str,
	assoc_type: &'static str,
) -> (TokenStream, TokenStream) {
	let crate_ = generate_crate_access(HIDDEN_INCLUDES_ID);
	let trait_ = Ident::new(trait_, Span::call_site());
	let assoc_type = Ident::new(assoc_type, Span::call_site());

	let block = quote!( <#runtime as #crate_::runtime_api::#trait_>::#assoc_type );
	let block_id = quote!( #crate_::runtime_api::BlockId<#block> );

	let ts = (block, block_id);
	// println!("BLOCK AND BLOCK ID\n{}\n\n{}\n", ts.0, ts.1);
	ts
}

fn generate_node_block_and_block_id_ty(runtime: &Type) -> (TokenStream, TokenStream) {
	generate_block_and_block_id_ty(runtime, "GetNodeBlockType", "NodeBlock")
}

fn generate_runtime_api_base_structures(impls: &[ItemImpl]) -> Result<TokenStream> {
	let crate_ = generate_crate_access(HIDDEN_INCLUDES_ID);
	let runtime = &impls.get(0).ok_or_else(||
		Error::new(Span::call_site(), "No api implementation given!")
	)?.self_ty;
	let (block, block_id) = generate_node_block_and_block_id_ty(runtime);

	Ok(quote!(
		pub struct RuntimeApi {}
		/// Implements all runtime apis for the client side.
		#[cfg(any(feature = "std", test))]
		pub struct RuntimeApiImpl<C: #crate_::runtime_api::CallRuntimeAt<#block> + 'static> {
			call: &'static C,
			commit_on_success: ::std::cell::RefCell<bool>,
			initialised_block: ::std::cell::RefCell<Option<#block_id>>,
			changes: ::std::cell::RefCell<#crate_::runtime_api::OverlayedChanges>,
		}

		// `RuntimeApi` itself is not threadsafe. However, an instance is only available in a
		// `ApiRef` object and `ApiRef` also has an associated lifetime. This lifetimes makes it
		// impossible to move `RuntimeApi` into another thread.
		#[cfg(any(feature = "std", test))]
		unsafe impl<C: #crate_::runtime_api::CallRuntimeAt<#block>> Send for RuntimeApiImpl<C> {}
		#[cfg(any(feature = "std", test))]
		unsafe impl<C: #crate_::runtime_api::CallRuntimeAt<#block>> Sync for RuntimeApiImpl<C> {}

		#[cfg(any(feature = "std", test))]
		impl<C: #crate_::runtime_api::CallRuntimeAt<#block>> #crate_::runtime_api::ApiExt<#block>
			for RuntimeApiImpl<C>
		{
			fn map_api_result<F: FnOnce(&Self) -> ::std::result::Result<R, E>, R, E>(
				&self,
				map_call: F
			) -> ::std::result::Result<R, E> where Self: Sized {
				*self.commit_on_success.borrow_mut() = false;
				let res = map_call(self);
				*self.commit_on_success.borrow_mut() = true;

				self.commit_on_ok(&res);

				res
			}

			fn has_api<A: #crate_::runtime_api::RuntimeApiInfo + ?Sized>(
				&self,
				at: &#block_id
			) -> #crate_::error::Result<bool> where Self: Sized {
				self.call.runtime_version_at(at).map(|r| r.has_api::<A>())
			}
		}

		#[cfg(any(feature = "std", test))]
		impl<C: #crate_::runtime_api::CallRuntimeAt<#block> + 'static>
			#crate_::runtime_api::ConstructRuntimeApi<#block, C> for RuntimeApi
		{
			type RuntimeApi = RuntimeApiImpl<C>;

			fn construct_runtime_api<'a>(
				call: &'a C,
			) -> #crate_::runtime_api::ApiRef<'a, Self::RuntimeApi> {
				RuntimeApiImpl {
					call: unsafe { ::std::mem::transmute(call) },
					commit_on_success: true.into(),
					initialised_block: None.into(),
					changes: Default::default(),
				}.into()
			}
		}

		#[cfg(any(feature = "std", test))]
		impl<C: #crate_::runtime_api::CallRuntimeAt<#block>> RuntimeApiImpl<C> {
			fn call_api_at<
				R: #crate_::runtime_api::Encode + #crate_::runtime_api::Decode + PartialEq,
				NC: FnOnce() -> ::std::result::Result<R, &'static str> + ::std::panic::UnwindSafe,
			>(
				&self,
				at: &#block_id,
				function: &'static str,
				args: Vec<u8>,
				native_call: NC,
				context: #crate_::runtime_api::ExecutionContext
			) -> #crate_::error::Result<R> {
				let res = unsafe {
					self.call.call_api_at(
						at,
						function,
						args,
						&mut *self.changes.borrow_mut(),
						&mut *self.initialised_block.borrow_mut(),
						Some(native_call),
						context
					).and_then(|r|
						match r {
							#crate_::runtime_api::NativeOrEncoded::Native(n) => {
								Ok(n)
							},
							#crate_::runtime_api::NativeOrEncoded::Encoded(r) => {
								R::decode(&mut &r[..])
									.ok_or_else(||
										#crate_::error::ErrorKind::CallResultDecode(
											function
										).into()
									)
							}
						}
					)
				};

				self.commit_on_ok(&res);
				res
			}

			fn commit_on_ok<R, E>(&self, res: &::std::result::Result<R, E>) {
				if *self.commit_on_success.borrow() {
					if res.is_err() {
						self.changes.borrow_mut().discard_prospective();
					} else {
						self.changes.borrow_mut().commit_prospective();
					}
				}
			}
		}
	))
}

/// Extend the given trait path with module that contains the declaration of the trait for the
/// runtime.
fn extend_with_runtime_decl_path(mut trait_: Path) -> Path {
	let runtime = {
		let trait_name = &trait_
			.segments
			.last()
			.as_ref()
			.expect("Trait path should always contain at least one item; qed")
			.value()
			.ident;

		generate_runtime_mod_name_for_trait(trait_name)
	};

	let pos = trait_.segments.len() - 1;
	trait_.segments.insert(pos, runtime.clone().into());
	trait_
}

/// Generates the implementations of the apis for the runtime.
fn generate_api_impl_for_runtime(impls: &[ItemImpl]) -> Result<TokenStream> {
	let mut impls_prepared = Vec::new();

	// We put `runtime` before each trait to get the trait that is intended for the runtime and
	// we put the `RuntimeBlock` as first argument for the trait generics.
	for impl_ in impls.iter() {
		let mut impl_ = impl_.clone();
		let trait_ = extract_impl_trait(&impl_)?.clone();
		let trait_ = extend_with_runtime_decl_path(trait_);
		impl_.trait_.as_mut().unwrap().1 = trait_;
		impls_prepared.push(impl_);
	}
	Ok(quote!( #( #impls_prepared )* ))
}


/// Auxilariy data structure that is used to convert `impl Api for Runtime` to
/// `impl Api for RuntimeApi`.
/// This requires us to replace the runtime `Block` with the node `Block`,
/// `impl Api for Runtime` with `impl Api for RuntimeApi` and replace the method implementations
/// with code that calls into the runtime.
struct ApiRuntimeImplToApiRuntimeApiImpl<'a> {
	node_block: &'a TokenStream,
	runtime_block: &'a TypePath,
	node_block_id: &'a TokenStream,
	impl_trait_ident: &'a Ident,
	runtime_mod_path: &'a Path,
	runtime_type: &'a Type,
	trait_generic_arguments: &'a [GenericArgument],
}

impl<'a> Fold for ApiRuntimeImplToApiRuntimeApiImpl<'a> {
	fn fold_type_path(&mut self, input: TypePath) -> TypePath {
		let new_ty_path = if input == *self.runtime_block {
			let node_block = self.node_block;
			parse_quote!( #node_block )
		} else {
			input
		};

		fold::fold_type_path(self, new_ty_path)
	}

	fn fold_fn_decl(&mut self, input: FnDecl) -> FnDecl {
		let input = fold_fn_decl_for_client_side(
			input,
			&self.node_block_id,
			&generate_crate_access(HIDDEN_INCLUDES_ID)
		);

		fold::fold_fn_decl(self, input)
	}

	fn fold_impl_item_method(&mut self, mut input: syn::ImplItemMethod) -> syn::ImplItemMethod {
		let block = {
			let crate_ = generate_crate_access(HIDDEN_INCLUDES_ID);
			let mut generated_name_counter = 0;
			// Replace `_` with unique patterns and collect all patterns.
			let arg_names = input.sig.decl.inputs.iter_mut().filter_map(|i| match i {
				FnArg::Captured(ref mut arg) => Some(&mut arg.pat),
				_ => None,
			}).map(|p| {
				*p = generate_unique_pattern(p.clone(), &mut generated_name_counter);
				p.clone()
			}).collect::<Vec<_>>();

			let runtime_mod_path = self.runtime_mod_path;
			let runtime = self.runtime_type;
			let mut arg_names2 = arg_names.clone();
			let mut fn_name = prefix_function_with_trait(self.impl_trait_ident, &input.sig.ident);
			let trait_generic_arguments = self.trait_generic_arguments;
			let node_block = self.node_block;

			let execution_context: syn::FnArg = parse_quote!( ExecutionContext::Other );
			let mut call_generator_name = input.sig.ident.to_string();
			let native_call_generator_ident =
				generate_native_call_generator_fn_name(&call_generator_name);
			
			// Generate the new method implementation that calls into the runtime.
			parse_quote!(
				{
					let args = #crate_::runtime_api::Encode::encode(&( #( &#arg_names ),* ));
					self.call_api_at(
						at,
						#fn_name,
						args,
						#runtime_mod_path #native_call_generator_ident ::
							<#runtime, #node_block #(, #trait_generic_arguments )*> (
							#( #arg_names2 ),*
						),
						#execution_context
					)
				}
			)
		};

		let mut input =	fold::fold_impl_item_method(self, input);
		// We need to set the block, after we modified the rest of the ast, otherwise we would
		// modify our generated block as well.
		input.block = block;
		input
	}

	fn fold_item_impl(&mut self, mut input: ItemImpl) -> ItemImpl {
		// Implement the trait for the `RuntimeApiImpl`
		input.self_ty = Box::new(parse_quote!( RuntimeApiImpl<RuntimeApiImplCall> ));

		let crate_ = generate_crate_access(HIDDEN_INCLUDES_ID);
		let block = self.node_block;
		input.generics.params.push(
			parse_quote!( RuntimeApiImplCall: #crate_::runtime_api::CallRuntimeAt<#block> + 'static )
		);

		// The implementation for the `RuntimeApiImpl` is only required when compiling with
		// the feature `std` or `test`.
		input.attrs.push(parse_quote!( #[cfg(any(feature = "std", test))] ));

		input = fold::fold_item_impl(self, input);

		let context_arg: syn::FnArg = parse_quote!( context: ExecutionContext );
		let mut methods_with_context = vec![];

		for item in &input.items {
			if let ImplItem::Method(method) = item {
				let mut ctx_method = method.clone();
				let mut stmt = ctx_method.block.stmts.pop().unwrap();
				if let syn::Stmt::Expr(ref mut method_call) = stmt {
					if let syn::Expr::MethodCall(ref mut expr) = method_call {
						expr.args.pop();
						let default_context = parse_quote!( context );
						expr.args.push(default_context);
					}
				}
				ctx_method.sig.ident = Ident::new(&format!("{}_with_context", &ctx_method.sig.ident), Span::call_site());
				ctx_method.sig.decl.inputs.push(context_arg.clone());
				ctx_method.block.stmts.push(stmt);
				methods_with_context.push(ImplItem::Method(ctx_method.clone()));
			}
		}
		
		input.items.extend(methods_with_context);
		input
	}

}

/// Generate the implementations of the runtime apis for the `RuntimeApi` type.
fn generate_api_impl_for_runtime_api(impls: &[ItemImpl]) -> Result<TokenStream> {
	let mut result = Vec::with_capacity(impls.len());

	for impl_ in impls {
		let impl_trait_path = extract_impl_trait(&impl_)?;
		let impl_trait = &impl_trait_path
			.segments
			.last()
			.ok_or_else(|| Error::new(impl_trait_path.span(), "Empty trait path not possible!"))?
			.into_value();
		let impl_trait_ident = &impl_trait.ident;
		let runtime_block = extract_runtime_block_ident(impl_trait_path)?;
		let (node_block, node_block_id) = generate_node_block_and_block_id_ty(&impl_.self_ty);
		let runtime_type = &impl_.self_ty;
		let mut runtime_mod_path = extend_with_runtime_decl_path(impl_trait_path.clone());
		// remove the trait to get just the module path
		runtime_mod_path.segments.pop();

		let trait_generic_arguments = match impl_trait.arguments {
			PathArguments::Parenthesized(_) | PathArguments::None => vec![],
			PathArguments::AngleBracketed(ref b) => b.args.iter().cloned().collect(),
		};
		let mut visitor = ApiRuntimeImplToApiRuntimeApiImpl {
			runtime_block,
			node_block: &node_block,
			node_block_id: &node_block_id,
			impl_trait_ident: &impl_trait_ident,
			runtime_mod_path: &runtime_mod_path,
			runtime_type: &*runtime_type,
			trait_generic_arguments: &trait_generic_arguments,
		
		};

		result.push(visitor.fold_item_impl(impl_.clone()));
	}
	Ok(quote!( #( #result )* ))
}

/// Generates `RUNTIME_API_VERSIONS` that holds all version information about the implemented
/// runtime apis.
fn generate_runtime_api_versions(impls: &[ItemImpl]) -> Result<TokenStream> {
	let mut result = Vec::with_capacity(impls.len());
	let mut processed_traits = HashSet::new();

	for impl_ in impls {
		let mut path = extend_with_runtime_decl_path(extract_impl_trait(&impl_)?.clone());
		// Remove the trait
		let trait_ = path
			.segments
			.pop()
			.expect("extract_impl_trait already checks that this is valid; qed")
			.into_value()
			.ident;

		let span = trait_.span();
		if !processed_traits.insert(trait_) {
			return Err(
				Error::new(
					span,
					"Two traits with the same name detected! \
					The trait name is used to generate its ID. \
					Please rename one trait at the declaration!"
				)
			)
		}

		let id: Path = parse_quote!( #path ID );
		let version: Path = parse_quote!( #path VERSION );

		result.push(quote!( (#id, #version) ));
	}

	let c = generate_crate_access(HIDDEN_INCLUDES_ID);

	Ok(quote!(
		const RUNTIME_API_VERSIONS: #c::runtime_api::ApisVec =
			#c::runtime_api::create_apis_vec!([ #( #result ),* ]);
	))
}

/// The implementation of the `impl_runtime_apis!` macro.
pub fn impl_runtime_apis_impl(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
	// Parse all impl blocks
	let RuntimeApiImpls { impls: mut api_impls } = parse_macro_input!(input as RuntimeApiImpls);
	
	let dispatch_impl = unwrap_or_error(generate_dispatch_function(&api_impls));
	let api_impls_for_runtime = unwrap_or_error(generate_api_impl_for_runtime(&api_impls));
	let base_runtime_api = unwrap_or_error(generate_runtime_api_base_structures(&api_impls));
	let hidden_includes = generate_hidden_includes(HIDDEN_INCLUDES_ID);
	let runtime_api_versions = unwrap_or_error(generate_runtime_api_versions(&api_impls));
	let wasm_interface = unwrap_or_error(generate_wasm_interface(&api_impls));
	
	// generate_impl_with_context(&mut api_impls);

	let api_impls_for_runtime_api = unwrap_or_error(generate_api_impl_for_runtime_api(&api_impls));

	quote!(
		#hidden_includes

		#base_runtime_api

		#api_impls_for_runtime

		#api_impls_for_runtime_api

		#runtime_api_versions

		pub mod api {
			use super::*;

			#dispatch_impl

			#wasm_interface
		}
	).into()
}
