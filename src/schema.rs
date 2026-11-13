// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use crate::types::{JsonObject, PromptArgs, PromptArgument, RpcError, CODE_INVALID_PARAMS};

pub(crate) fn validate_tool_args(schema: &Value, args: &JsonObject) -> Result<(), RpcError> {
    let Some(schema_obj) = schema.as_object() else {
        return Ok(());
    };
    if let Some(required) = schema_obj.get("required").and_then(Value::as_array) {
        for entry in required {
            if let Some(name) = entry.as_str() {
                match args.get(name) {
                    Some(val) if !val.is_null() => {}
                    _ => {
                        return Err(invalid_params(format!(
                            "missing required argument {name:?}"
                        )));
                    }
                }
            }
        }
    }
    let props = schema_obj.get("properties").and_then(Value::as_object);
    if schema_obj.get("additionalProperties") == Some(&Value::Bool(false)) {
        for key in args.keys() {
            if !props.is_some_and(|p| p.contains_key(key)) {
                return Err(invalid_params(format!(
                    "unexpected argument {key:?} is not permitted by inputSchema"
                )));
            }
        }
    }
    if let Some(props_map) = props {
        validate_property_types(props_map, args)?;
    }
    Ok(())
}

fn validate_property_types(
    props: &serde_json::Map<String, Value>,
    args: &JsonObject,
) -> Result<(), RpcError> {
    for (key, val) in args {
        let Some(want_type) = props
            .get(key)
            .and_then(Value::as_object)
            .and_then(|m| m.get("type"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if !matches_json_type(want_type, val) {
            return Err(invalid_params(format!(
                "argument {key:?} must be of type {want_type}"
            )));
        }
    }
    Ok(())
}

fn matches_json_type(want: &str, val: &Value) -> bool {
    match want {
        "string" => val.is_string(),
        "boolean" => val.is_boolean(),
        "number" => val.is_number(),
        "integer" => {
            val.is_i64()
                || val.is_u64()
                || val
                    .as_f64()
                    .is_some_and(|n| n.is_finite() && n.fract() == 0.0)
        }
        "object" => val.is_object(),
        "array" => val.is_array(),
        _ => !val.is_null(),
    }
}

pub(crate) fn validate_prompt_args(
    declared: &[PromptArgument],
    args: &PromptArgs,
) -> Result<(), RpcError> {
    for arg in declared {
        if arg.required && args.get(&arg.name).is_none_or(|v| v.trim().is_empty()) {
            return Err(invalid_params(format!(
                "missing required prompt argument {:?}",
                arg.name
            )));
        }
    }
    Ok(())
}

fn invalid_params(message: String) -> RpcError {
    RpcError {
        code: CODE_INVALID_PARAMS,
        message,
        data: None,
    }
}
