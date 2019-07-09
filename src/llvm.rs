use crate::parser::*;
use failure::Error;
use llvm_sys::analysis::{LLVMVerifierFailureAction, LLVMVerifyFunction};
use llvm_sys::core::{
    LLVMAddFunction, LLVMAppendBasicBlock, LLVMArrayType, LLVMBuildAdd, LLVMBuildAnd,
    LLVMBuildCall, LLVMBuildCondBr, LLVMBuildFAdd, LLVMBuildFCmp, LLVMBuildFDiv, LLVMBuildFMul,
    LLVMBuildFSub, LLVMBuildGlobalStringPtr, LLVMBuildICmp, LLVMBuildMul, LLVMBuildNeg,
    LLVMBuildOr, LLVMBuildRet, LLVMBuildSub, LLVMConstArray, LLVMConstInt,
    LLVMConstIntGetZExtValue, LLVMConstNull, LLVMConstStruct, LLVMConstStructInContext,
    LLVMContextCreate, LLVMContextDispose, LLVMCreateBuilderInContext, LLVMDisposeBuilder,
    LLVMDisposeModule, LLVMFunctionType, LLVMGetIntTypeWidth, LLVMGetParam, LLVMGetReturnType,
    LLVMGetTypeKind, LLVMIntTypeInContext, LLVMModuleCreateWithNameInContext, LLVMPointerType,
    LLVMStructCreateNamed, LLVMStructSetBody, LLVMStructTypeInContext, LLVMTypeOf,
    LLVMValueAsBasicBlock, LLVMVoidType, LLVMBuildAShr, LLVMBuildShl, LLVMBuildXor, LLVMBuildFRem,
    LLVMBuildInsertElement,
};
use llvm_sys::prelude::*;
use llvm_sys::{LLVMBuilder, LLVMIntPredicate, LLVMModule, LLVMRealPredicate, LLVMTypeKind};
use std::collections::HashMap;
use std::ffi::CString;
use std::str::FromStr;

const LLVM_FALSE: LLVMBool = 0 as LLVMBool;
const LLVM_TRUE: LLVMBool = 1 as LLVMBool;

struct Module {
    module: *mut LLVMModule,
    strings: Vec<CString>,
}

impl Module {
    fn new(module_name: &str, context: LLVMContextRef) -> Result<Module, Error> {
        let c_module_name = CString::new(module_name)?;
        Ok(Module {
            module: unsafe {
                LLVMModuleCreateWithNameInContext(
                    c_module_name.to_bytes_with_nul().as_ptr() as *const _,
                    context,
                )
            },
            strings: vec![c_module_name],
        })
    }
    fn new_string_ptr(&mut self, s: &str) -> *const i8 {
        self.new_mut_string_ptr(s)
    }

    fn new_mut_string_ptr(&mut self, s: &str) -> *mut i8 {
        let cstring = CString::new(s).unwrap();
        let ptr = cstring.as_ptr() as *mut _;
        self.strings.push(cstring);
        ptr
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe {
            LLVMDisposeModule(self.module);
        }
    }
}

struct Builder {
    builder: *mut LLVMBuilder,
}

impl Builder {
    fn new(context: LLVMContextRef) -> Builder {
        unsafe {
            Builder {
                builder: LLVMCreateBuilderInContext(context),
            }
        }
    }
}

impl Drop for Builder {
    fn drop(&mut self) {
        unsafe { LLVMDisposeBuilder(self.builder) }
    }
}

#[derive(Debug, Fail)]
pub enum CodeGenerationError {
    #[fail(display = "Number parsing error {}", 0)]
    NumberParsingError(String),
    #[fail(display = "(Un)Fixed point numbers are not a stable feature")]
    FixedPointNumbersNotStable,
    #[fail(display = "User defined type {} not found", 0)]
    UserDefinedTypeNotFound(String),
    #[fail(display = "User defined type {} has no default value", 0)]
    UserDefinedTypeHasNoDefault(String),
    #[fail(display = "Array length has to be integral")]
    InvalidArrayLength,
    #[fail(display = "Expecting boolean expression")]
    ExpectingBooleanExpression,
    #[fail(display = "Expecting integer expression")]
    ExpectingIntegerExpression,
    #[fail(display = "Expecting function expression")]
    ExpectingFunctionExpression,
    #[fail(display = "Invalid function")]
    InvalidFunction,
    #[fail(display = "Item not callable")]
    ItemNotCallable,
    #[fail(display = "Argument not of expected kind {:?}", 0)]
    InvalidArgumentKind(LLVMTypeKind),
    #[fail(display = "Expected lvalue, got rvalue.")]
    ExpectedLValue,
    #[fail(display = "Invalid placeholder")]
    InvalidPlaceholder,
    #[fail(display = "Modifier call with no function call")]
    ModifierCallWithoutFunctionCall,
}

pub struct Context {
    context: LLVMContextRef,
    module: Module,
    builder: Builder,
    symbols: HashMap<String, LLVMValueRef>,
    type_symbols: HashMap<String, LLVMTypeRef>,
    function_modifiers: HashMap<LLVMValueRef, Vec<FunctionDefinitionModifier>>,
    function_modifiers_stack: Vec<LLVMValueRef>,
}

impl Context {
    pub fn new(name: &str) -> Result<Context, Error> {
        let context = unsafe { LLVMContextCreate() };
        Ok(Context {
            context,
            module: Module::new(name, context)?,
            builder: Builder::new(context),
            symbols: HashMap::new(),
            type_symbols: HashMap::new(),
            function_modifiers: HashMap::new(),
            function_modifiers_stack: Vec::new(),
        })
    }
    pub fn print_to_file(&self, _file: &str) -> Result<(), Vec<String>> {
        Ok(())
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { LLVMContextDispose(self.context) };
    }
}

pub trait CodeGenerator {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError>;
}

pub trait TypeGenerator {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError>;
}

fn number_cast(origin: LLVMValueRef, destiny: LLVMTypeRef) -> LLVMValueRef {
    let origin_type = unsafe { LLVMTypeOf(origin) };
    let origin_type_kind = unsafe { LLVMGetTypeKind(origin_type) };
    let destiny_type_kind = unsafe { LLVMGetTypeKind(destiny) };
    match (origin_type_kind, destiny_type_kind) {
        _ => panic!("How did you arrive here?"),
    }
}

fn cmp(
    context: &mut Context,
    common_type: LLVMTypeRef,
    converted_left_value: LLVMValueRef,
    converted_right_value: LLVMValueRef,
) -> LLVMValueRef {
    let type_kind = unsafe { LLVMGetTypeKind(common_type) };
    match type_kind {
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildICmp(
                context.builder.builder,
                LLVMIntPredicate::LLVMIntEQ,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("equals"),
            )
        },
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFCmp(
                context.builder.builder,
                LLVMRealPredicate::LLVMRealOEQ,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("equals"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn not_cmp(
    context: &mut Context,
    common_type: LLVMTypeRef,
    converted_left_value: LLVMValueRef,
    converted_right_value: LLVMValueRef,
) -> LLVMValueRef {
    let type_kind = unsafe { LLVMGetTypeKind(common_type) };
    match type_kind {
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildICmp(
                context.builder.builder,
                LLVMIntPredicate::LLVMIntNE,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("equals"),
            )
        },
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFCmp(
                context.builder.builder,
                LLVMRealPredicate::LLVMRealONE,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("equals"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn gt(
    context: &mut Context,
    common_type: LLVMTypeRef,
    converted_left_value: LLVMValueRef,
    converted_right_value: LLVMValueRef,
) -> LLVMValueRef {
    let type_kind = unsafe { LLVMGetTypeKind(common_type) };
    match type_kind {
        /*
        TODO: Think how to store signed type information
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildICmp(
                context.builder.builder,
                LLVMIntPredicate::LLVMIn,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        */
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFCmp(
                context.builder.builder,
                LLVMRealPredicate::LLVMRealOGT,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn lt(
    context: &mut Context,
    common_type: LLVMTypeRef,
    converted_left_value: LLVMValueRef,
    converted_right_value: LLVMValueRef,
) -> LLVMValueRef {
    let type_kind = unsafe { LLVMGetTypeKind(common_type) };
    match type_kind {
        /*
        TODO: Think how to store signed type information
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildICmp(
                context.builder.builder,
                LLVMIntPredicate::LLVMIn,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        */
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFCmp(
                context.builder.builder,
                LLVMRealPredicate::LLVMRealOLT,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn ge(
    context: &mut Context,
    common_type: LLVMTypeRef,
    converted_left_value: LLVMValueRef,
    converted_right_value: LLVMValueRef,
) -> LLVMValueRef {
    let type_kind = unsafe { LLVMGetTypeKind(common_type) };
    match type_kind {
        /*
        TODO: Think how to store signed type information
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildICmp(
                context.builder.builder,
                LLVMIntPredicate::LLVMIn,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        */
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFCmp(
                context.builder.builder,
                LLVMRealPredicate::LLVMRealOGE,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn le(
    context: &mut Context,
    common_type: LLVMTypeRef,
    converted_left_value: LLVMValueRef,
    converted_right_value: LLVMValueRef,
) -> LLVMValueRef {
    let type_kind = unsafe { LLVMGetTypeKind(common_type) };
    match type_kind {
        /*
        TODO: Think how to store signed type information
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildICmp(
                context.builder.builder,
                LLVMIntPredicate::LLVMIn,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        */
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFCmp(
                context.builder.builder,
                LLVMRealPredicate::LLVMRealOLE,
                converted_left_value,
                converted_right_value,
                context.module.new_string_ptr("greater than"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn pow(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    match kind {
        LLVMTypeKind::LLVMIntegerTypeKind => {
            unsafe {
                LLVMBuildMul(
                    context.builder.builder,
                    left,
                    right,
                    context.module.new_string_ptr("multiply integer"),
                )
            }
        },
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFMul(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("multiply float"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn multiply(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    match kind {
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildMul(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("multiply integer"),
            )
        },
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFMul(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("multiply float"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn add(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    match kind {
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildAdd(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("add integer"),
            )
        },
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFAdd(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("add float"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn sub(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    match kind {
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildSub(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("sub integer"),
            )
        },
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFSub(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("sub float"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn div(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    match kind {
        /*
        TODO: Handle signed integer.
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildSub(context.builder.builder, left, right, context.module.new_string_ptr("sub integer"))
        },
        */
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFDiv(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("sub float"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn shl(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    unsafe {
        LLVMBuildShl(
            context.builder.builder,
            left,
            right,
            context.module.new_string_ptr("SHL"),
        )
    }
}

fn shr(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    unsafe {
        LLVMBuildAShr(
            context.builder.builder,
            left,
            right,
            context.module.new_string_ptr("SHR"),
        )
    }
}

fn rem(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    match kind {
        /*
        TODO: Handle signed integer.
        LLVMTypeKind::LLVMIntegerTypeKind => unsafe {
            LLVMBuildSub(context.builder.builder, left, right, context.module.new_string_ptr("sub integer"))
        },
        */
        LLVMTypeKind::LLVMFloatTypeKind => unsafe {
            LLVMBuildFRem(
                context.builder.builder,
                left,
                right,
                context.module.new_string_ptr("rem float"),
            )
        },
        _ => panic!("How did you arrive here?"),
    }
}

fn xor(
    context: &mut Context,
    kind: LLVMTypeKind,
    left: LLVMValueRef,
    right: LLVMValueRef,
) -> LLVMValueRef {
    unsafe {
        LLVMBuildXor(
            context.builder.builder,
            left,
            right,
            context.module.new_string_ptr("SHR"),
        )
    }
}

impl<'a> CodeGenerator for BinaryExpression {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let common_type = type_cohesion(self.left.typegen(context)?, self.right.typegen(context)?)?;
        let converted_left_value = number_cast(self.left.codegen(context)?, common_type);
        let converted_right_value = number_cast(self.right.codegen(context)?, common_type);
        let type_kind = unsafe { LLVMGetTypeKind(common_type) };
        match self.op {
            BinaryOperator::Ampersand => Ok(unsafe {
                LLVMBuildAnd(
                    context.builder.builder,
                    converted_left_value,
                    converted_right_value,
                    context.module.new_string_ptr("build and"),
                )
            }),
            BinaryOperator::AmpersandEquals => {
                let value = unsafe {
                    LLVMBuildAnd(
                        context.builder.builder,
                        converted_left_value,
                        converted_right_value,
                        context.module.new_string_ptr("build and"),
                    )
                };
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::BangEquals => Ok(not_cmp(
                context,
                common_type,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::Bar => Ok(unsafe {
                LLVMBuildOr(
                    context.builder.builder,
                    converted_left_value,
                    converted_right_value,
                    context.module.new_string_ptr("build or"),
                )
            }),
            BinaryOperator::BarEquals => {
                let value = unsafe {
                    LLVMBuildOr(
                        context.builder.builder,
                        converted_left_value,
                        converted_right_value,
                        context.module.new_string_ptr("build or"),
                    )
                };
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::BiggerOrEqualsThan => Ok(ge(
                context,
                common_type,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::BiggerThan => Ok(gt(
                context,
                common_type,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::Dash => Ok(sub(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::DashEquals => {
                let value = sub(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            }
            BinaryOperator::DoubleAmpersand => {
                let not_converted_left_value = unsafe {
                    LLVMBuildNeg(
                        context.builder.builder,
                        converted_left_value,
                        context.module.new_string_ptr("not on and"),
                    )
                };
                Ok(ternary(
                    context,
                    not_converted_left_value,
                    converted_left_value,
                    converted_right_value,
                ))
            }
            BinaryOperator::DoubleBar => Ok(ternary(
                context,
                converted_left_value,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::DoubleBiggerThan => Ok(shr(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::DoubleBiggerThanEquals => {
                let value = shr(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::DoubleEquals => Ok(cmp(
                context,
                common_type,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::DoubleLesserThan => Ok(shl(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::DoubleLesserThanEquals => {
                let value = shl(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::DoubleStar => Ok(pow(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::Equals => {
                let value = self.right.codegen(context)?;
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::Hat => Ok(xor(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::HatEquals => {
                let value = xor(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            }
            BinaryOperator::LesserOrEqualsThan => Ok(le(
                context,
                common_type,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::LesserThan => Ok(lt(
                context,
                common_type,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::Percent => Ok(rem(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::PercentEquals => {
                let value = rem(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::Plus => Ok(add(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::PlusEquals => {
                let value = add(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::Slash => Ok(div(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::SlashEquals => {
                let value = div(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            },
            BinaryOperator::Star => Ok(multiply(
                context,
                type_kind,
                converted_left_value,
                converted_right_value,
            )),
            BinaryOperator::StarEquals => {
                let value = multiply(
                    context,
                    type_kind,
                    converted_left_value,
                    converted_right_value,
                );
                self.perform_expression_side_effects(context, value)
            },
        }
    }
}


impl<'a> CodeGenerator for Literal {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self {
            Literal::StringLiteral(s) => Ok(unsafe {
                LLVMBuildGlobalStringPtr(
                    context.builder.builder,
                    context.module.new_string_ptr(s),
                    context.module.new_string_ptr("tempstring"),
                )
            }),
            Literal::HexLiteral(s) => Ok(unsafe {
                let value = usize::from_str(s).map_err(|_| {
                    CodeGenerationError::NumberParsingError(s.to_owned().to_owned())
                })?;
                let bits = find_int_size_in_bits(value);
                let t = uint(context, bits as u32);
                LLVMConstInt(t, value as u64, LLVM_FALSE)
            }),
            Literal::BooleanLiteral(b) => {
                Ok(unsafe { LLVMConstInt(uint(context, 1), *b as _, LLVM_FALSE) })
            }
            Literal::NumberLiteral { value: s, unit: _ } => Ok(unsafe {
                let value = usize::from_str(s).map_err(|_| {
                    CodeGenerationError::NumberParsingError(s.to_owned().to_owned())
                })?;
                let bits = find_int_size_in_bits(value);
                let t = uint(context, bits as u32);
                LLVMConstInt(t, value as u64, LLVM_TRUE)
            }),
        }
    }
}

impl<'a> CodeGenerator for PrimaryExpression {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self {
            PrimaryExpression::Literal(l) => l.codegen(context),
            PrimaryExpression::Identifier(i) => {
                Ok(context.symbols.get(i.as_str()).unwrap().clone())
            }
            PrimaryExpression::TupleExpression(exps) => {
                let maybe_values: Vec<LLVMValueRef> =
                    exps.iter()
                        .map(|e| e.codegen(context))
                        .collect::<Result<Vec<LLVMValueRef>, CodeGenerationError>>()?;
                let mut values: Vec<LLVMValueRef> = maybe_values.into_iter().collect();
                Ok(unsafe { LLVMConstStruct(values.as_mut_ptr(), values.len() as u32, LLVM_TRUE) })
            }
            PrimaryExpression::ElementaryTypeName(etn) => {
                Ok(unsafe { LLVMConstNull(etn.typegen(context)?) })
            }
        }
    }
}

fn ternary(
    context: &mut Context,
    condition: LLVMValueRef,
    if_branch: LLVMValueRef,
    else_branch: LLVMValueRef,
) -> LLVMValueRef {
    let if_branch_block = unsafe { LLVMValueAsBasicBlock(if_branch) };
    let else_branch_block = unsafe { LLVMValueAsBasicBlock(else_branch) };
    unsafe {
        LLVMBuildCondBr(
            context.builder.builder,
            condition,
            if_branch_block,
            else_branch_block,
        )
    }
}

impl<'a> CodeGenerator for Expression {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self {
            Expression::PrimaryExpression(pe) => pe.codegen(context),
            Expression::GroupExpression(e) => e.codegen(context),
            Expression::LeftUnaryExpression(lue) => lue.codegen(context),
            Expression::RightUnaryExpression(rue) => rue.codegen(context),
            Expression::FunctionCall(f) => f.codegen(context),
            Expression::TernaryOperator(condition, if_branch, else_branch) => {
                let c = condition.codegen(context)?;
                let i = if_branch.codegen(context)?;
                let e = else_branch.codegen(context)?;
                Ok(ternary(context, c, i, e))
            }
            Expression::BinaryExpression(be) => be.codegen(context),
            Expression::MemberAccess(_object, _property) => unimplemented!(),
            Expression::IndexAccess(_collection, _index) => unimplemented!(),
            Expression::NewExpression(_tn) => unimplemented!(),
        }
    }
}

impl<'a> TypeGenerator for Literal {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self {
            Literal::BooleanLiteral(_) => Ok(uint(context, 1)),
            Literal::HexLiteral(_) => {
                let s = self.codegen(context)?;
                Ok(unsafe { LLVMTypeOf(s) })
            }
            Literal::NumberLiteral { .. } => {
                let s = self.codegen(context)?;
                Ok(unsafe { LLVMTypeOf(s) })
            }
            Literal::StringLiteral(_) => {
                let s = self.codegen(context)?;
                Ok(unsafe { LLVMTypeOf(s) })
            }
        }
    }
}

impl<'a> TypeGenerator for PrimaryExpression {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self {
            PrimaryExpression::TupleExpression(exps) => {
                let mut types: Vec<LLVMTypeRef> = exps
                    .iter()
                    .map(|e| e.typegen(context))
                    .collect::<Result<Vec<LLVMTypeRef>, CodeGenerationError>>()?;
                let tuple_type = unsafe {
                    LLVMStructTypeInContext(
                        context.context,
                        types.as_mut_ptr(),
                        types.len() as u32,
                        LLVM_TRUE,
                    )
                };
                Ok(tuple_type)
            }
            PrimaryExpression::Identifier(id) => Ok(unsafe { LLVMTypeOf(self.codegen(context)?) }),
            PrimaryExpression::ElementaryTypeName(etn) => etn.typegen(context),
            PrimaryExpression::Literal(l) => l.typegen(context),
        }
    }
}

impl<'a> TypeGenerator for FunctionCall {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let callee_type = self.callee.typegen(context)?;
        if unsafe { LLVMGetTypeKind(callee_type) } == LLVMTypeKind::LLVMFunctionTypeKind {
            Ok(unsafe { LLVMGetReturnType(callee_type) })
        } else {
            Err(CodeGenerationError::ItemNotCallable)
        }
    }
}

fn type_cohesion(
    left_type: LLVMTypeRef,
    right_type: LLVMTypeRef,
) -> Result<LLVMTypeRef, CodeGenerationError> {
    let left_type_kind = unsafe { LLVMGetTypeKind(left_type) };
    let right_type_kind = unsafe { LLVMGetTypeKind(right_type) };
    if left_type_kind != LLVMTypeKind::LLVMIntegerTypeKind
        && left_type_kind != LLVMTypeKind::LLVMDoubleTypeKind
        && left_type_kind != LLVMTypeKind::LLVMFloatTypeKind
    {
        Err(CodeGenerationError::InvalidArgumentKind(left_type_kind))?
    }
    if right_type_kind != LLVMTypeKind::LLVMIntegerTypeKind
        && right_type_kind != LLVMTypeKind::LLVMDoubleTypeKind
        && right_type_kind != LLVMTypeKind::LLVMFloatTypeKind
    {
        Err(CodeGenerationError::InvalidArgumentKind(right_type_kind))?
    }
    match (left_type_kind, right_type_kind) {
        (LLVMTypeKind::LLVMDoubleTypeKind, _) => Ok(left_type),
        (_, LLVMTypeKind::LLVMDoubleTypeKind) => Ok(right_type),
        (LLVMTypeKind::LLVMFloatTypeKind, _) => Ok(left_type),
        (_, LLVMTypeKind::LLVMFloatTypeKind) => Ok(right_type),
        (LLVMTypeKind::LLVMIntegerTypeKind, LLVMTypeKind::LLVMIntegerTypeKind) => {
            let left_size = unsafe { LLVMGetIntTypeWidth(left_type) };
            let right_size = unsafe { LLVMGetIntTypeWidth(right_type) };
            if left_size >= right_size {
                Ok(left_type)
            } else {
                Ok(right_type)
            }
        }
        _ => panic!("YOU SHOULDN'T BE HERE"),
    }
}

impl<'a> TypeGenerator for BinaryExpression {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self.op {
            BinaryOperator::Ampersand
            | BinaryOperator::AmpersandEquals
            | BinaryOperator::Bar
            | BinaryOperator::BarEquals
            | BinaryOperator::DoubleBiggerThan
            | BinaryOperator::DoubleLesserThan
            | BinaryOperator::DoubleBiggerThanEquals
            | BinaryOperator::DoubleLesserThanEquals
            | BinaryOperator::Hat
            | BinaryOperator::HatEquals => {
                let left_type = self.left.typegen(context)?;
                let right_type = self.right.typegen(context)?;
                type_cohesion(left_type, right_type)
            }
            BinaryOperator::BangEquals => Ok(uint(context, 1)),
            BinaryOperator::BiggerOrEqualsThan => Ok(uint(context, 1)),
            BinaryOperator::BiggerThan => Ok(uint(context, 1)),
            BinaryOperator::DoubleAmpersand => Ok(uint(context, 1)),
            BinaryOperator::DoubleBar => Ok(uint(context, 1)),
            BinaryOperator::DoubleEquals => Ok(uint(context, 1)),
            BinaryOperator::LesserOrEqualsThan => Ok(uint(context, 1)),
            BinaryOperator::LesserThan => Ok(uint(context, 1)),
            BinaryOperator::Equals => self.right.typegen(context),
            _ => unimplemented!(),
        }
    }
}

impl<'a> TypeGenerator for LeftUnaryExpression {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self.op {
            LeftUnaryOperator::Bang => Ok(uint(context, 1)),
            _ => self.value.typegen(context),
        }
    }
}

impl<'a> TypeGenerator for RightUnaryExpression {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        self.value.typegen(context)
    }
}

impl<'a> TypeGenerator for Expression {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self {
            Expression::PrimaryExpression(p) => p.typegen(context),
            Expression::FunctionCall(fc) => fc.typegen(context),
            Expression::BinaryExpression(bc) => bc.typegen(context),
            Expression::GroupExpression(ge) => ge.typegen(context),
            Expression::LeftUnaryExpression(lue) => lue.typegen(context),
            Expression::NewExpression(t) => t.typegen(context),
            Expression::RightUnaryExpression(rue) => rue.typegen(context),
            Expression::TernaryOperator(_, _, _) => {
                Ok(unsafe { LLVMTypeOf(self.codegen(context)?) })
            }
            Expression::IndexAccess(_collection, _index) => unimplemented!(),
            Expression::MemberAccess(_object, _property) => unimplemented!(),
        }
    }
}

impl<'a> CodeGenerator for SimpleStatement {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self {
            SimpleStatement::ExpressionStatement(e) => e.codegen(context),
            SimpleStatement::VariableDefinition(vs, v) => {
                let t = vs.0[0].type_name.typegen(context)?;
                let value = if let Some(e) = v {
                    e.codegen(context)?
                } else {
                    unsafe {
                        LLVMConstNull(t)
                    }
                };
                for v in &vs.0 {
                    context.symbols.insert(
                        v.identifier.0.to_owned(),
                        value.clone(),
                    );
                }
                Ok(value)
            },
        }
    }
}

impl<'a> CodeGenerator for Statement {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self {
            Statement::Block(b) => {
                b.iter().fold(Ok(unsafe {
                    LLVMConstNull(uint(context, 1))
                }), |_, s| {
                    s.codegen(context)
                })
            },
            Statement::IfStatement(is) => {
                let condition = is.condition.codegen(context)?;
                let if_branch = unsafe {
                    LLVMValueAsBasicBlock(is.true_branch.codegen(context)?)
                };
                let else_branch = if let Some(e) = &is.false_branch {
                    unsafe {
                        LLVMValueAsBasicBlock(e.codegen(context)?)
                    }
                } else {
                    unsafe {
                        LLVMValueAsBasicBlock(LLVMConstNull(uint(context, 1)))
                    }
                };
                Ok(unsafe {
                    LLVMBuildCondBr(context.builder.builder, condition, if_branch, else_branch)
                })
            },
            Statement::SimpleStatement(ss) => ss.codegen(context),
            Statement::PlaceholderStatement =>
                context.function_modifiers_stack.pop().ok_or(CodeGenerationError::InvalidPlaceholder),
            _ => unimplemented!(),
        }
    }
}

fn function_call_arguments_to_values(
    context: &mut Context,
    arguments: &FunctionCallArguments,
) -> Result<Vec<LLVMValueRef>, CodeGenerationError> {
    match arguments {
        FunctionCallArguments::ExpressionList(es) => {
            es.iter().map(|e| e.codegen(context)).collect()
        }
        // TODO: Name values can be out of order
        FunctionCallArguments::NameValueList(ns) => {
            ns.iter().map(|n| n.value.codegen(context)).collect()
        }
    }
}

impl<'a> CodeGenerator for FunctionCall {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let function_type = self.callee.typegen(context)?;
        if unsafe { LLVMGetTypeKind(function_type) } == LLVMTypeKind::LLVMFunctionTypeKind {
            let function = self.callee.codegen(context)?;
            let mut arguments = function_call_arguments_to_values(context, &self.arguments)?;
            let function_call = unsafe {
                LLVMBuildCall(
                    context.builder.builder,
                    function,
                    arguments.as_mut_ptr(),
                    arguments.len() as u32,
                    context.module.new_string_ptr("tmpcall"),
                )
            };
            context.function_modifiers_stack.push(function_call);
            Ok(function_call)
        } else {
            Err(CodeGenerationError::ExpectingFunctionExpression)
        }
    }
}

impl<'a> CodeGenerator for RightUnaryExpression {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self.op {
            RightUnaryOperator::DoubleDash => {
                // TODO: Update symbols
                self.value.codegen(context)
            }
            RightUnaryOperator::DoublePlus => {
                // TODO: Update symbols
                self.value.codegen(context)
            }
        }
    }
}

impl<'a> CodeGenerator for LeftUnaryExpression {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self.op {
            LeftUnaryOperator::Bang => {
                let exp_type = self.value.typegen(context)?;
                let bits = unsafe { LLVMGetIntTypeWidth(exp_type) };
                if unsafe { LLVMGetTypeKind(exp_type) } == LLVMTypeKind::LLVMIntegerTypeKind
                    && bits == 1
                {
                    let int_value = self.value.codegen(context)?;
                    Ok(unsafe {
                        LLVMBuildNeg(
                            context.builder.builder,
                            int_value,
                            context.module.new_string_ptr("tmpneg"),
                        )
                    })
                } else {
                    Err(CodeGenerationError::ExpectingBooleanExpression)
                }
            }
            LeftUnaryOperator::DoubleDash => {
                // TODO: Update symbols
                let exp_type = self.value.typegen(context)?;
                if unsafe { LLVMGetTypeKind(exp_type) } == LLVMTypeKind::LLVMIntegerTypeKind {
                    let int_value = self.value.codegen(context)?;
                    Ok(unsafe {
                        LLVMBuildSub(
                            context.builder.builder,
                            int_value,
                            LLVMConstInt(uint(context, 1), 1, LLVM_FALSE),
                            context.module.new_string_ptr("tmpsub"),
                        )
                    })
                } else {
                    Err(CodeGenerationError::ExpectingIntegerExpression)
                }
            }
            LeftUnaryOperator::DoublePlus => {
                // TODO: Update symbols
                let exp_type = self.value.typegen(context)?;
                if unsafe { LLVMGetTypeKind(exp_type) } == LLVMTypeKind::LLVMIntegerTypeKind {
                    let int_value = self.value.codegen(context)?;
                    Ok(unsafe {
                        LLVMBuildAdd(
                            context.builder.builder,
                            int_value,
                            LLVMConstInt(uint(context, 1), 1, LLVM_FALSE),
                            context.module.new_string_ptr("tmpadd"),
                        )
                    })
                } else {
                    Err(CodeGenerationError::ExpectingIntegerExpression)
                }
            }
            LeftUnaryOperator::Dash => {
                let exp_type = self.value.typegen(context)?;
                if unsafe { LLVMGetTypeKind(exp_type) } == LLVMTypeKind::LLVMIntegerTypeKind {
                    let int_value = self.value.codegen(context)?;
                    let bits = unsafe { LLVMGetIntTypeWidth(exp_type) };
                    let mask_type = uint(context, bits);
                    let mask = unsafe { LLVMConstInt(mask_type, 2u64.pow(bits), LLVM_TRUE) };
                    Ok(unsafe {
                        LLVMBuildOr(
                            context.builder.builder,
                            int_value,
                            mask,
                            context.module.new_string_ptr("tmpxor"),
                        )
                    })
                } else {
                    Err(CodeGenerationError::ExpectingIntegerExpression)
                }
            }
            LeftUnaryOperator::Home => {
                let exp_type = self.value.typegen(context)?;
                if unsafe { LLVMGetTypeKind(exp_type) } == LLVMTypeKind::LLVMIntegerTypeKind {
                    let int_value = self.value.codegen(context)?;
                    Ok(unsafe {
                        LLVMBuildNeg(
                            context.builder.builder,
                            int_value,
                            context.module.new_string_ptr("tmpneg"),
                        )
                    })
                } else {
                    Err(CodeGenerationError::ExpectingIntegerExpression)
                }
            }
            LeftUnaryOperator::Plus => {
                let exp_type = self.value.typegen(context)?;
                if unsafe { LLVMGetTypeKind(exp_type) } == LLVMTypeKind::LLVMIntegerTypeKind {
                    let int_value = self.value.codegen(context)?;
                    let bits = unsafe { LLVMGetIntTypeWidth(exp_type) };
                    let mask_type = uint(context, bits);
                    let mask = unsafe { LLVMConstInt(mask_type, !2u64.pow(bits), LLVM_TRUE) };
                    Ok(unsafe {
                        LLVMBuildAnd(
                            context.builder.builder,
                            int_value,
                            mask,
                            context.module.new_string_ptr("tmpand"),
                        )
                    })
                } else {
                    Err(CodeGenerationError::ExpectingIntegerExpression)
                }
            }
            // TODO: Update symbols
            // TODO: Map LLVMTypeRef to TypeName
            LeftUnaryOperator::Delete => unimplemented!(),
        }
    }
}

impl TypeGenerator for ElementaryTypeName {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self {
            ElementaryTypeName::String => Ok(unsafe { LLVMPointerType(uint(context, 8), 0) }),
            ElementaryTypeName::Address => Ok(uint(context, 8 * 20)),
            ElementaryTypeName::Bool => Ok(uint(context, 1)),
            ElementaryTypeName::Byte(b) => Ok(uint(context, *b as u32 * 8)),
            ElementaryTypeName::Uint(b) => Ok(uint(context, *b as u32 * 8)),
            ElementaryTypeName::Int(b) => Ok(uint(context, *b as u32 * 8)),
            ElementaryTypeName::Fixed(_, _) | ElementaryTypeName::Ufixed(_, _) => {
                Err(CodeGenerationError::FixedPointNumbersNotStable)
            }
        }
    }
}

fn type_from_type_name(
    type_name: &TypeName,
    context: &mut Context,
) -> Result<LLVMTypeRef, CodeGenerationError> {
    match type_name {
        TypeName::ElementaryTypeName(e) => e.typegen(context),
        TypeName::ArrayTypeName(t, None) => Ok(unsafe { LLVMArrayType(t.typegen(context)?, 0) }),
        TypeName::ArrayTypeName(t, Some(e)) => {
            let et = e.typegen(context)?;
            if unsafe { LLVMGetTypeKind(et) } != LLVMTypeKind::LLVMIntegerTypeKind {
                Err(CodeGenerationError::InvalidArrayLength)?
            };
            let t = t.typegen(context)?;
            let v = e.codegen(context)?;
            let size = unsafe { LLVMConstIntGetZExtValue(v) } as u32;
            Ok(unsafe { LLVMArrayType(t, size) })
        }
        TypeName::UserDefinedTypeName(user_defined_type_name) => context
            .type_symbols
            .get(user_defined_type_name.base.as_str())
            .ok_or(CodeGenerationError::UserDefinedTypeNotFound(
                user_defined_type_name.base.as_str().to_owned(),
            ))
            .map(|v| v.clone()),
        TypeName::Address => Ok(uint(context, 20 * 8)),
        TypeName::AddressPayable => Ok(uint(context, 20 * 8)),
        TypeName::Mapping(k, v) => {
            let key_type = k.typegen(context)?;
            let value_type = v.typegen(context)?;
            Ok(mapping(context, key_type, value_type))
        }
        TypeName::FunctionTypeName(f) => {
            let return_type = f.return_values[0].type_name.typegen(context)?;
            let mut param_types: Vec<LLVMTypeRef> = f
                .arguments
                .iter()
                .map(|p| p.type_name.typegen(context))
                .collect::<Result<Vec<LLVMTypeRef>, CodeGenerationError>>()?;
            Ok(unsafe {
                LLVMFunctionType(
                    return_type,
                    param_types.as_mut_ptr(),
                    param_types.len() as u32,
                    LLVM_FALSE,
                )
            })
        }
    }
}

impl TypeGenerator for TypeName {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        Ok(type_from_type_name(self, context)?)
    }
}

impl TypeGenerator for FunctionDefinition {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let mut return_types = self
            .return_values
            .iter()
            .map(|p| type_from_type_name(&p.type_name, context).unwrap())
            .collect::<Vec<LLVMTypeRef>>();
        let mut parameter_types = self
            .parameters
            .iter()
            .map(|p| type_from_type_name(&p.type_name, context).unwrap())
            .collect::<Vec<LLVMTypeRef>>();
        let return_type = unsafe {
            LLVMStructTypeInContext(
                context.context,
                return_types.as_mut_ptr(),
                self.return_values.len() as u32,
                LLVM_TRUE,
            )
        };
        Ok(unsafe {
            LLVMFunctionType(
                return_type,
                parameter_types.as_mut_ptr(),
                self.parameters.len() as u32,
                LLVM_FALSE,
            )
        })
    }
}

impl TypeGenerator for Vec<Parameter> {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let mut return_types = self
            .iter()
            .map(|p| type_from_type_name(&p.type_name, context).unwrap())
            .collect::<Vec<LLVMTypeRef>>();
        Ok(unsafe {
            LLVMStructTypeInContext(
                context.context,
                return_types.as_mut_ptr(),
                self.len() as u32,
                LLVM_TRUE,
            )
        })
    }
}

impl TypeGenerator for VariableDeclaration {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        self.type_name.typegen(context)
    }
}

impl TypeGenerator for StructDefinition {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let mut struct_types = self
            .variables
            .0
            .iter()
            .map(|p| type_from_type_name(&p.type_name, context).unwrap())
            .collect::<Vec<LLVMTypeRef>>();
        Ok(unsafe {
            LLVMStructTypeInContext(
                context.context,
                struct_types.as_mut_ptr(),
                struct_types.len() as u32,
                LLVM_TRUE,
            )
        })
    }
}

impl TypeGenerator for EventDefinition {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let mut event_types = self
            .parameters
            .iter()
            .map(|p| type_from_type_name(&p.type_name, context).unwrap())
            .collect::<Vec<LLVMTypeRef>>();
        event_types.push(uint(context, 1));
        Ok(unsafe {
            LLVMStructTypeInContext(
                context.context,
                event_types.as_mut_ptr(),
                event_types.len() as u32,
                LLVM_TRUE,
            )
        })
    }
}

impl TypeGenerator for EnumDefinition {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let mut counter = 0;
        let s = find_int_size_in_bits(self.values.len());
        let t = uint(context, s as u32);
        for member in self.values.iter() {
            let member_symbol = format!("{}_{}", self.name.as_str(), member.as_str());
            let value = unsafe { LLVMConstInt(t, counter as u64, LLVM_FALSE) };
            context.symbols.insert(member_symbol, value.clone());
            if counter == 0 {
                context
                    .symbols
                    .insert(format!("{}@default", self.name.as_str()), value.clone());
            }
            counter += 1;
        }
        context
            .type_symbols
            .insert(self.name.as_str().to_owned(), t);
        Ok(t)
    }
}

impl TypeGenerator for ContractPart {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        match self {
            ContractPart::EnumDefinition(e) => e.typegen(context),
            ContractPart::EventDefinition(e) => e.typegen(context),
            ContractPart::FunctionDefinition(f) => f.typegen(context),
            ContractPart::ModifierDefinition(m) => m.typegen(context),
            ContractPart::StateVariableDeclaration(s) => {
                Ok(type_from_type_name(&s.type_name, context)?)
            }
            ContractPart::StructDefinition(s) => s.typegen(context),
            ContractPart::UsingForDeclaration(_) => unimplemented!(),
        }
    }
}

fn default_value(
    context: &mut Context,
    ty: &TypeName,
) -> Result<LLVMValueRef, CodeGenerationError> {
    match ty {
        TypeName::ElementaryTypeName(e) => match e {
            ElementaryTypeName::String => Ok(unsafe {
                LLVMBuildGlobalStringPtr(
                    context.builder.builder,
                    context.module.new_string_ptr(""),
                    context.module.new_string_ptr("tempstr"),
                )
            }),
            ElementaryTypeName::Address => {
                Ok(unsafe { LLVMConstInt(uint(context, 20), 0, LLVM_FALSE) })
            }
            ElementaryTypeName::Bool => {
                Ok(unsafe { LLVMConstInt(uint(context, 1), 0, LLVM_FALSE) })
            }
            ElementaryTypeName::Byte(b) => {
                Ok(unsafe { LLVMConstInt(uint(context, *b as u32 * 8), 0, LLVM_FALSE) })
            }
            ElementaryTypeName::Uint(b) => {
                Ok(unsafe { LLVMConstInt(uint(context, *b as u32 * 8), 0, LLVM_FALSE) })
            }
            ElementaryTypeName::Int(b) => {
                Ok(unsafe { LLVMConstInt(uint(context, *b as u32 * 8), 0, LLVM_TRUE) })
            }
            ElementaryTypeName::Fixed(_, _) | ElementaryTypeName::Ufixed(_, _) => {
                Err(CodeGenerationError::FixedPointNumbersNotStable)
            }
        },
        TypeName::ArrayTypeName(_, _) => Ok(unsafe { LLVMConstNull(ty.typegen(context)?) }),
        TypeName::UserDefinedTypeName(user_defined_type_name) => context
            .symbols
            .get(&format!("{}@default", user_defined_type_name.base.as_str()))
            .ok_or(CodeGenerationError::UserDefinedTypeHasNoDefault(
                user_defined_type_name.base.as_str().to_owned(),
            ))
            .map(|v| v.clone()),
        TypeName::Address => Ok(unsafe { LLVMConstInt(uint(context, 20 * 8), 0, LLVM_FALSE) }),
        TypeName::AddressPayable => {
            Ok(unsafe { LLVMConstInt(uint(context, 20 * 8), 0, LLVM_FALSE) })
        }
        TypeName::Mapping(k, v) => {
            let key_type = k.typegen(context)?;
            let value_type = type_from_type_name(v, context)?;
            Ok(mapping_value(context, key_type, value_type))
        }
        TypeName::FunctionTypeName(_f) => {
            let function_type =
                unsafe { LLVMFunctionType(LLVMVoidType(), vec![].as_mut_ptr(), 0, LLVM_FALSE) };
            Ok(unsafe {
                LLVMAddFunction(
                    context.module.module,
                    context.module.new_string_ptr("null function"),
                    function_type,
                )
            })
        }
    }
}

impl<'a> CodeGenerator for StateVariableDeclaration {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        if let Some(e) = &self.value {
            e.codegen(context)
        } else {
            default_value(context, &self.type_name)
        }
    }
}

impl TypeGenerator for StateVariableDeclaration {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        self.type_name.typegen(context)
    }
}

impl CodeGenerator for ModifierDefinition {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let prototype = self.typegen(context)?;
        let function = unsafe {
            LLVMAddFunction(
                context.module.module,
                context.module.new_string_ptr("function"),
                prototype,
            )
        };
        let _bb = unsafe {
            LLVMAppendBasicBlock(function, context.module.new_string_ptr("function_block"))
        };
        let parameters = match &self.parameters {
            Some(p) => p.clone(),
            None => vec![],
        };
        for (i, p) in parameters.iter().enumerate() {
            match &p.identifier {
                Some(id) => {
                    let param = unsafe { LLVMGetParam(function, i as u32) };
                    context.symbols.insert(id.as_str().to_string(), param);
                }
                None => {}
            };
        }
        let return_type = uint(context, 1);
        let return_value = self
            .block
            .iter()
            .fold(unsafe { LLVMConstNull(return_type) }, |_r, s| {
                s.codegen(context).unwrap()
            });
        unsafe { LLVMBuildRet(context.builder.builder, return_value) };
        let result = unsafe {
            LLVMVerifyFunction(function, LLVMVerifierFailureAction::LLVMPrintMessageAction)
        };
        if result == 0 {
            Ok(function)
        } else {
            Err(CodeGenerationError::InvalidFunction)
        }
    }
}

impl TypeGenerator for ModifierDefinition {
    fn typegen(&self, context: &mut Context) -> Result<LLVMTypeRef, CodeGenerationError> {
        let v = context.function_modifiers_stack.last().ok_or(CodeGenerationError::ModifierCallWithoutFunctionCall)?.clone();
        Ok(unsafe {
            LLVMTypeOf(v)
        })
    }
}

impl CodeGenerator for FunctionDefinition {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let prototype = self.typegen(context)?;
        let function = unsafe {
            LLVMAddFunction(
                context.module.module,
                context.module.new_string_ptr("function"),
                prototype,
            )
        };
        let _bb = unsafe {
            LLVMAppendBasicBlock(function, context.module.new_string_ptr("function_block"))
        };
        for (i, p) in self.parameters.iter().enumerate() {
            match &p.identifier {
                Some(id) => {
                    let param = unsafe { LLVMGetParam(function, i as u32) };
                    context.symbols.insert(id.as_str().to_string(), param);
                }
                None => {}
            };
        }
        let return_type = self.return_values.typegen(context)?;
        let return_value = match &self.body {
            Some(b) => b
                .iter()
                .fold(unsafe { LLVMConstNull(return_type) }, |_r, s| {
                    s.codegen(context).unwrap()
                }),
            None => unsafe { LLVMConstNull(return_type) },
        };
        unsafe { LLVMBuildRet(context.builder.builder, return_value) };
        let result = unsafe {
            LLVMVerifyFunction(function, LLVMVerifierFailureAction::LLVMPrintMessageAction)
        };
        if result == 0 {
            context.function_modifiers.insert(function, self.modifiers.clone());;
            if let Some(id) = &self.name {
                context.symbols.insert(id.0.to_owned(), function);
                context.type_symbols.insert(id.0.to_owned(), prototype);
            }
            Ok(function)
        } else {
            Err(CodeGenerationError::InvalidFunction)
        }
    }
}

impl<'a> CodeGenerator for EnumDefinition {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let t = self.typegen(context)?;
        Ok(unsafe { LLVMConstInt(t, 0 as u64, LLVM_FALSE) })
    }
}

impl<'a> CodeGenerator for EventDefinition {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let t = self.typegen(context)?;
        Ok(unsafe { LLVMConstNull(t) })
    }
}

impl<'a> CodeGenerator for StructDefinition {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let t = self.typegen(context)?;
        Ok(unsafe { LLVMConstNull(t) })
    }
}

impl<'a> CodeGenerator for ContractPart {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        match self {
            ContractPart::EnumDefinition(e) => e.codegen(context),
            ContractPart::EventDefinition(e) => e.codegen(context),
            ContractPart::FunctionDefinition(f) => f.codegen(context),
            ContractPart::ModifierDefinition(f) => f.codegen(context),
            ContractPart::StateVariableDeclaration(svd) => svd.codegen(context),
            ContractPart::StructDefinition(s) => s.codegen(context),
            ContractPart::UsingForDeclaration(_) => unimplemented!(),
        }
    }
}

impl<'a> CodeGenerator for Program {
    fn codegen(&self, context: &mut Context) -> Result<LLVMValueRef, CodeGenerationError> {
        let mut last = None;
        let non_empty_list = &self.0;
        for s in non_empty_list.0.iter() {
            match s {
                SourceUnit::ContractDefinition(c) => {
                    context.symbols.clear();
                    let struct_type = unsafe {
                        LLVMStructCreateNamed(
                            context.context,
                            context.module.new_string_ptr(c.name.as_str()),
                        )
                    };
                    let mut types = Vec::new();
                    let mut vals = Vec::new();
                    for t in c.contract_parts.iter() {
                        let et = t.typegen(context)?;
                        let val = t.codegen(context)?;
                        types.push(et.clone());
                        vals.push(val.clone());
                        let name = match &t {
                            ContractPart::ModifierDefinition(m) => m.name.as_str().to_owned(),
                            ContractPart::StateVariableDeclaration(svd) => {
                                svd.name.as_str().to_owned()
                            }
                            ContractPart::FunctionDefinition(f) => f
                                .name
                                .clone()
                                .unwrap_or(Identifier("".to_owned()))
                                .as_str()
                                .to_owned(),
                            ContractPart::StructDefinition(s) => s.name.as_str().to_owned(),
                            ContractPart::EventDefinition(e) => e.name.as_str().to_owned(),
                            ContractPart::EnumDefinition(e) => e.name.as_str().to_owned(),
                            ContractPart::UsingForDeclaration(_) => panic!("Can't happen"),
                        };
                        context.symbols.insert(name.clone(), val.clone());
                        if let ContractType::Library = c.contract_type {
                            context.symbols.insert(
                                format!("{}.{}", c.name.as_str().to_owned(), name.clone()),
                                val,
                            );
                            context.type_symbols.insert(
                                format!("{}.{}", c.name.as_str().to_owned(), name.clone()),
                                et,
                            );
                        }
                    }
                    unsafe {
                        LLVMStructSetBody(
                            struct_type,
                            types.as_mut_ptr(),
                            types.len() as u32,
                            LLVM_TRUE,
                        )
                    };
                    let contract = unsafe {
                        LLVMConstStructInContext(
                            context.context,
                            vals.as_mut_ptr(),
                            vals.len() as u32,
                            LLVM_TRUE,
                        )
                    };
                    context.symbols.insert(c.name.as_str().to_owned(), contract);
                    last = Some(contract.clone());
                }
                SourceUnit::ImportDirective(_) => unimplemented!(),
                SourceUnit::PragmaDirective(_) => unimplemented!(),
            }
        }
        Ok(last.unwrap())
    }
}

fn mapping(context: &mut Context, key: LLVMTypeRef, value: LLVMTypeRef) -> LLVMTypeRef {
    let mapping_name = format!("mapping<{:?}, {:?}>", key, value);
    let internal_array_type = unsafe { LLVMPointerType(value, 0) };
    let size_type = uint(context, 32);
    let get_function_type =
        unsafe { LLVMFunctionType(value, vec![key].as_mut_ptr(), 0, LLVM_FALSE) };
    let set_function_type =
        unsafe { LLVMFunctionType(LLVMVoidType(), vec![key, value].as_mut_ptr(), 0, LLVM_FALSE) };
    let struct_type = unsafe {
        LLVMStructCreateNamed(
            context.context,
            context.module.new_string_ptr(mapping_name.as_str()),
        )
    };
    let mut types = vec![
        internal_array_type,
        size_type,
        get_function_type,
        set_function_type,
    ];
    unsafe {
        LLVMStructSetBody(
            struct_type,
            types.as_mut_ptr(),
            types.len() as u32,
            1 as LLVMBool,
        )
    };
    struct_type
}

fn mapping_value(context: &mut Context, key: LLVMTypeRef, value: LLVMTypeRef) -> LLVMValueRef {
    let mapping_name = format!("mapping<{:?}, {:?}>", key, value);
    let internal_array_type = unsafe { LLVMPointerType(value, 0) };
    let internal_array = unsafe { LLVMConstArray(internal_array_type, Vec::new().as_mut_ptr(), 0) };
    let size_type = uint(context, 32);
    let size = unsafe { LLVMConstInt(size_type, 0, LLVM_FALSE) };
    let get_function_type =
        unsafe { LLVMFunctionType(value, vec![key].as_mut_ptr(), 1, LLVM_FALSE) };
    let get_function = unsafe {
        LLVMAddFunction(
            context.module.module,
            context
                .module
                .new_string_ptr(format!("{}.get", mapping_name).as_str()),
            get_function_type,
        )
    };
    let set_function_type =
        unsafe { LLVMFunctionType(LLVMVoidType(), vec![key, value].as_mut_ptr(), 2, LLVM_FALSE) };
    let set_function = unsafe {
        LLVMAddFunction(
            context.module.module,
            context
                .module
                .new_string_ptr(format!("{}.set", mapping_name).as_str()),
            set_function_type,
        )
    };
    let mut vals = vec![internal_array, size, get_function, set_function];
    unsafe {
        LLVMConstStructInContext(
            context.context,
            vals.as_mut_ptr(),
            vals.len() as u32,
            LLVM_TRUE,
        )
    }
}

#[inline]
fn uint(context: &Context, bits: u32) -> LLVMTypeRef {
    unsafe { LLVMIntTypeInContext(context.context, bits) }
}

#[inline]
fn find_int_size_in_bits(number: usize) -> usize {
    let mut start = 8;
    while 2usize.pow(start as u32) < number {
        start += 8;
    }
    start
}

#[inline]
fn hash_function(context: &mut Context) -> LLVMValueRef {
    let u32_type = uint(context, 8 * 32);
    let function_type =
        unsafe { LLVMFunctionType(u32_type, vec![u32_type].as_mut_ptr(), 2, LLVM_FALSE) };
    let function = unsafe {
        LLVMAddFunction(
            context.module.module,
            context.module.new_string_ptr("hash"),
            function_type,
        )
    };
    let _block = unsafe { LLVMAppendBasicBlock(function, context.module.new_string_ptr("entry")) };
    function
}

impl BinaryExpression {
    fn perform_expression_side_effects(&self, context: &mut Context, value: LLVMValueRef) -> Result<LLVMValueRef, CodeGenerationError> {
        match &*self.left {
            Expression::PrimaryExpression(PrimaryExpression::Identifier(id)) => {
                context.symbols.insert(
                    id.0.to_owned(),
                    value,
                );
                Ok(())
            },
            Expression::IndexAccess(array_expression, member_expression) => {
                let vec_val = array_expression.codegen(context)?;
                let ind_val = member_expression.codegen(context)?;
                unsafe {
                    LLVMBuildInsertElement(context.builder.builder, vec_val, value, ind_val, context.module.new_string_ptr("Update array in &="))
                };
                Ok(())
            },
            // TODO: Side effect for dictionaries and structs too
            _ => Err(CodeGenerationError::ExpectedLValue),
        }?;
        Ok(value)
    }
}
