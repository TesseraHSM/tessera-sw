// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Procedural macros for API testing infrastructure.
//!
//! This crate provides custom test attribute macros that enhance standard Rust tests
//! with tracing support and specialized test setup for API testing scenarios.

use proc_macro::*;
use quote::quote;
use syn::spanned::*;
use syn::*;

/// Attribute macro for creating API tests with tracing support.
///
/// This macro wraps a test function to automatically initialize tracing
/// and create a tracing span for the test execution. The test function
/// must be synchronous and take no arguments.
///
/// # Constraints
///
/// - The function must not be async
/// - The function must not have any parameters
///
/// # Errors
///
/// Returns a compile error if:
/// - The function is marked as async
/// - The function has any parameters
#[proc_macro_attribute]
pub fn api_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    make_api_test(item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Attribute macro for creating partition-based API tests with tracing support.
///
/// This macro is similar to `api_test` but designed for tests that require
/// a partition parameter. It wraps the test function to automatically initialize
/// tracing, create a tracing span, and provide a partition object via the
/// `with_partition` utility function.
///
/// # Constraints
///
/// - The function must not be async
/// - The function must accept exactly one parameter (the partition)
///
/// # Errors
///
/// Returns a compile error if:
/// - The function is marked as async
#[proc_macro_attribute]
pub fn partition_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    make_partition_test(item)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Attribute macro for creating session-based API tests with tracing support.
///
/// This macro is similar to `api_test` but designed for tests that require
/// a session parameter. It wraps the test function to automatically initialize
/// tracing, create a tracing span, and provide a session object via the
/// `with_session` utility function.
///
/// # Constraints
///
/// - The function must not be async
/// - The function must accept exactly one parameter (the session)
///
/// # Errors
///
/// Returns a compile error if:
/// - The function is marked as async
///
/// # Session Selection
///
/// The session kind is selected at runtime for the whole test run.
///
/// The test crate uses `open_session` by default. Setting
/// `api_rev=1_1` in `TSRA_TEST_ARGS` selects `open_session_ex` instead.
///
/// `#[session_test(api_rev_at_least(1, 1))]` runs the test only when the
/// selected revision is at least 1.1; otherwise it returns before any
/// partition setup. It calls `crate::utils::session::api_rev_at_least`.
#[proc_macro_attribute]
pub fn session_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let min_rev = if attr.is_empty() {
        None
    } else {
        Some(parse_macro_input!(attr with parse_min_api_rev))
    };
    make_session_test(item, min_rev)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// Parses `api_rev_at_least(MAJOR, MINOR)` into `(MAJOR, MINOR)`.
fn parse_min_api_rev(input: parse::ParseStream<'_>) -> syn::Result<(LitInt, LitInt)> {
    let ident: syn::Ident = input.parse()?;
    if ident != "api_rev_at_least" {
        return Err(Error::new(
            ident.span(),
            "expected `api_rev_at_least(MAJOR, MINOR)`",
        ));
    }
    let args;
    parenthesized!(args in input);
    let major: LitInt = args.parse()?;
    args.parse::<Token![,]>()?;
    let minor: LitInt = args.parse()?;
    major.base10_parse::<u32>()?;
    minor.base10_parse::<u32>()?;
    Ok((major, minor))
}

/// Generates the implementation for the `api_test` attribute macro.
///
/// This function transforms the input test function into a test that:
/// 1. Initializes tracing
/// 2. Acquires the shared partition lock
/// 3. Creates a named tracing span for the test
/// 4. Enters the span and executes the original test function
///
/// # Arguments
///
/// * `item` - The function item to transform into an API test
///
/// # Returns
///
/// Returns a token stream representing the transformed test function,
/// or an error if the function signature is invalid.
fn make_api_test(item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.fn_token.span(),
            "test function must not be async",
        ));
    }

    let name = &item.sig.ident;
    let return_type = &item.sig.output;
    if !item.sig.inputs.is_empty() {
        return Err(Error::new(item.sig.inputs.span(), "expected 0 arguments"));
    };
    let attrs = &item.attrs;

    Ok(quote! {
        #[::core::prelude::v1::test]
        #(#attrs)*
        fn #name() #return_type {
            #item
            crate::utils::api::init();
            let _partition_guard = crate::utils::partition::PARTITION_LOCK.lock();
            let span = tracing::span!(tracing::Level::INFO, stringify!(#name));
            let _span_guard = span.enter();
            #name()
        }
    })
}

/// Generates the implementation for the `partition_test` attribute macro.
///
/// This function transforms the input test function into a test that:
/// 1. Initializes tracing
/// 2. Creates a named tracing span for the test
/// 3. Enters the span
/// 4. Provides a partition via the `with_partition` utility function
/// 5. Executes the original test function with the partition parameter
///
/// # Arguments
///
/// * `item` - The function item to transform into a partition-based API test
///
/// # Returns
///
/// Returns a token stream representing the transformed test function,
/// or an error if the function signature is invalid.
fn make_partition_test(item: ItemFn) -> syn::Result<proc_macro2::TokenStream> {
    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.fn_token.span(),
            "test function must not be async",
        ));
    }

    let name = &item.sig.ident;
    let return_type = &item.sig.output;
    let attrs = &item.attrs;

    Ok(quote! {
        #[::core::prelude::v1::test]
        #(#attrs)*
        fn #name() #return_type {
            #item
            crate::utils::api::init();
            let span = tracing::span!(tracing::Level::INFO, stringify!(#name), );
            let _span_guard = span.enter();
            crate::utils::partition::with_partition(|partition, creds| {
                #name(partition, creds)
            });
        }
    })
}

/// Generates the implementation for the `session_api_test` attribute macro.
///
/// This function transforms the input test function into a test that:
/// 1. Initializes tracing
/// 2. Creates a named tracing span for the test
/// 3. Enters the span
/// 4. Provides a session via the `with_session` utility function
/// 5. Executes the original test function with the session parameter
///
/// # Arguments
///
/// * `item` - The function item to transform into a session-based API test
///
/// # Returns
///
/// Returns a token stream representing the transformed test function,
/// or an error if the function signature is invalid.
fn make_session_test(
    item: ItemFn,
    min_rev: Option<(LitInt, LitInt)>,
) -> syn::Result<proc_macro2::TokenStream> {
    if item.sig.asyncness.is_some() {
        return Err(Error::new(
            item.sig.fn_token.span(),
            "test function must not be async",
        ));
    }

    let name = &item.sig.ident;
    let return_type = &item.sig.output;
    let attrs = &item.attrs;
    let skip = min_rev.map(|(major, minor)| {
        quote! {
            if !crate::utils::session::api_rev_at_least(#major, #minor) {
                return;
            }
        }
    });

    Ok(quote! {
        #[::core::prelude::v1::test]
        #(#attrs)*
        fn #name() #return_type {
            #item
            #skip
            crate::utils::api::init();
            let span = tracing::span!(tracing::Level::INFO, stringify!(#name), );
            let _span_guard = span.enter();
            crate::utils::session::with_session(|session| {
                #name(session)
            });
        }
    })
}
