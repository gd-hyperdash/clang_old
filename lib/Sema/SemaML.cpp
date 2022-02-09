//===--------------------- SemaML.cpp - Sema ML extensions  -----------------===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

#include "clang/AST/DeclFriend.h"
#include "clang/Sema/ML.h"
#include "clang/Sema/SemaInternal.h"
#include "clang/Sema/SemaDiagnostic.h"
#include "clang/Sema/TemplateDeduction.h"

using namespace clang;
using namespace clang::sema;

//===-----------------------------------------------------------------------===//
// Types
//===-----------------------------------------------------------------------===//

struct ExtImpl {
  NamespaceDecl *NS = nullptr;
  ClassTemplateDecl *Impl = nullptr;

  explicit ExtImpl() = default;

  operator bool() const { return NS && Impl; }
};

//===-----------------------------------------------------------------------===//
// Globals
//===-----------------------------------------------------------------------===//

static auto constexpr ML_NS = "mlrt";
static auto constexpr ML_EXT_DATA = "MLExtensionImpl";

//===-----------------------------------------------------------------------===//
// Helpers
//===-----------------------------------------------------------------------===//

static bool checkMangling(const StringRef& S) {

}

static Expr *UnwrapDecoratorExpr(Expr *E) {
  if (auto UO = dyn_cast<UnaryOperator>(E)) {
    if (UO->getOpcode() == UnaryOperatorKind::UO_AddrOf) {
      return UO->getSubExpr();
    }
  }

  return E;
}

static QualType GetDecoratorType(Sema &S, FunctionDecl *D,
                                 CXXRecordDecl *Base) {
  QualType T;

  if (D->isTailDecorator()) {
    auto const TT = D->getTailTypeLoc();

    if (TT) {
      T = TT->getType();

      if (!T.isNull() && D->isCXXClassMember()) {
        // Set correct calling convention for tails.
        if (auto Ty = dyn_cast<FunctionProtoType>(T.getTypePtr())) {
          auto EPI = Ty->getExtProtoInfo();
          EPI.ExtInfo =
              EPI.ExtInfo.withCallingConv(CallingConv::CC_X86ThisCall);
          T = S.Context.getFunctionType(Ty->getReturnType(),
                                        Ty->getParamTypes(), EPI);
        }
      }
    }
  } else {
    T = D->getType();
  }

  if (!T.isNull()) {
    // Remove potential record qualifier.
    T = S.ExtractUnqualifiedFunctionType(T);

    // Member lookup requires the base qualifier.
    auto M = dyn_cast<CXXMethodDecl>(D);
    if (M && !M->isStatic()) {
      T = S.Context.getMemberPointerType(
          T, S.Context.getRecordType(Base).getTypePtr());
    }
  }

  return T;
}

static ExtImpl const FindExtensionImpl(TranslationUnitDecl *TU) {
  ExtImpl S;

  for (auto D : TU->decls()) {
    auto NS = dyn_cast<NamespaceDecl>(D);
    if (!NS || NS->getQualifiedNameAsString() != ML_NS)
      continue;

    for (auto R : NS->decls()) {
      auto Impl = dyn_cast<ClassTemplateDecl>(R);
      if (Impl && Impl->getName() == ML_EXT_DATA) {
        S.NS = NS;
        S.Impl = Impl;
        break;
      }
    }
  }

  return S;
}

//===-----------------------------------------------------------------------===//
// SemaExtension
//===-----------------------------------------------------------------------===//

ClassTemplateDecl *SemaExtension::CastTypeToTemplateClass(QualType T) {
  if (!T.isNull()) {
    if (auto TST = T->getAs<TemplateSpecializationType>()) {
      return dyn_cast<ClassTemplateDecl>(
          TST->getTemplateName().getAsTemplateDecl());
    }
  }

  return nullptr;
}

Expr *SemaExtension::GetBaseExpr(CXXRecordDecl *Base,
                                 const DeclarationNameInfo &DNI) {
  LookupResult R(S, DNI, Sema::LookupNameKind::LookupMemberName);

  // If the base is a specialization, make sure it's fully instantiated.
  if (auto Spec = dyn_cast<ClassTemplateSpecializationDecl>(Base)) {
    if (!ForceCompleteClassSpecialization(Spec)) {
      return nullptr;
    }
  }

  // Find all matching bases.
  S.LookupQualifiedName(R, Base);

  // Handle the lookup result.
  auto &Unresolved = R.asUnresolvedSet();

  if (Unresolved.size()) {
    auto M = cast<CXXMethodDecl>(*Unresolved.begin());

    // Build qualifier.
    auto Q = BuildRecordQualifier(Base);

    // Return as expression.
    return Unresolved.size() == 1
               ? BuildDeclRef(M, M->getType(), M->getNameInfo(), Q, true,
                              DNI.getLoc())
               : BuildLookup(Base, Q, DNI, Unresolved, true, DNI.getLoc());
  }

  return nullptr;
}

FunctionDecl *SemaExtension::FindBaseOfDecorator(FunctionDecl *D,
                                                 Expr *WrappedExpr) {
  FunctionDecl *FD = nullptr;
  CXXRecordDecl *BaseOrSpec = nullptr;
  bool HasCheckedType = false;

  // Defer uninstantiated templates.
  if (D->isTemplated() && !D->isTemplateInstantiation()) {
    DeferredDecorators.insert({D, WrappedExpr});
    return nullptr;
  }

  // Defer type checking for tails.
  if (D->isTailDecorator()) {
    HasCheckedType = true;
  }

  // Unwrap the expression.
  auto UnwrappedExpr = UnwrapDecoratorExpr(WrappedExpr);

  // Get base, if any.
  if (auto M = dyn_cast<CXXMethodDecl>(D)) {
    auto P = M->getParent();

    if (P->isRecordExtension()) {
      BaseOrSpec = P->getExtensionBase();
    }
  }

  // Handle dependant base.
  /*
  if (auto DSE = dyn_cast<DependentScopeDeclRefExpr>(UnwrappedExpr)) {
    llvm::SmallVector<TemplateArgument> TemplateArgs;
    assert(Ext && "No extension?");

    // Get template arguments.
    auto Q = Ext->getExtensionBaseLoc()->getType();
    auto TemplateBase = CastTypeToTemplateClass(Q);
    auto &ExtArgs =
        cast<ClassTemplateSpecializationDecl>(Ext)->getTemplateArgs();

    if (auto PartialSpecTy = Q->getAs<TemplateSpecializationType>()) {
        // TODO: This algorithm is very crappy.
      for (auto i = 0u; i < PartialSpecTy->getNumArgs(); ++i) {
        auto &A = PartialSpecTy->getArg(i);
        if (auto ATy = A.getAsType()->getAs<TemplateTypeParmType>()) {
          TemplateArgs.push_back(ExtArgs[ATy->getIndex()]);
        } else {
          TemplateArgs.push_back(A);
        }
      }
    }

    // Build specialization.
    BaseOrSpec = BuildClassSpecialization(TemplateBase, TemplateArgs);

    // Resolve base.
    WrappedExpr = GetBaseExpr(BaseOrSpec, DSE->getNameInfo());
    UnwrappedExpr = UnwrapDecoratorExpr(WrappedExpr);
  }
  */

  // Handle simple expression.
  if (auto DRE = dyn_cast<DeclRefExpr>(UnwrappedExpr)) {
    FD = cast<FunctionDecl>(DRE->getDecl());
  }

  // Handle lookups.
  if (auto ULE = dyn_cast<UnresolvedLookupExpr>(UnwrappedExpr)) {
    // Lookup base.
    auto DT = GetDecoratorType(S, D, BaseOrSpec);

    if (!DT.isNull() && ULE->isOverloaded()) {
      DeclAccessPair P;
      FD = S.ResolveAddressOfOverloadedFunction(WrappedExpr, DT, true, P);
      HasCheckedType = true;
    }
  }

  // Did we find a candidate?
  if (!FD) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_not_valid);
    return nullptr;
  }

  // If we havent done any type check, do it now.
  // TODO: maybe dont compare the stringifyed types smhsmh.
  if (!HasCheckedType &&
      D->getType().getAsString() != FD->getType().getAsString()) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_type_mismatch)
        << FD->getQualifiedNameAsString();
    return nullptr;
  }

  // Methods can only be decorated in the context of an extension.
  if (auto BaseMethod = dyn_cast<CXXMethodDecl>(FD)) {
    assert(BaseOrSpec && "No base?");
    // Method base and extension base must match.
    if (BaseOrSpec != BaseMethod->getParent()) {
      S.Diag(D->getLocation(), diag::err_decorator_argument_type_mismatch)
          << FD->getQualifiedNameAsString();
      return nullptr;
    }
  }

  // Decorators cannot decorate other decorators.
  if (FD->isDecorator()) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_is_decorator);
    return nullptr;
  }

  // Complete base type when needed.
  if (!ForceCompleteFunction(FD)) {
    S.Diag(FD->getLocation(), diag::err_decorator_argument_not_valid);
    return nullptr;
  }

  return FD;
}

TypeSourceInfo *SemaExtension::AttachExtensionBase(CXXRecordDecl *E,
                                                   TypeSourceInfo *B) {
  auto &Context = S.Context;
  auto TU = Context.getTranslationUnitDecl();

  // Defer templated extension.
  if (E->isTemplated() &&
      !isTemplateInstantiation(E->getTemplateSpecializationKind())) {
    auto TD = E->getDescribedClassTemplate();
    assert(TD && "No template?");
    DeferredExtensions.insert({TD, B});
    return B;
  }

  auto Data = FindExtensionImpl(TU);

  if (Data) {
    auto Base = B->getType()->getAsCXXRecordDecl();
    TemplateArgument ExtArg(Context.getRecordType(E));
    TemplateArgument BaseArg(B->getType().getCanonicalType());
    auto TemplateArgs =
        TemplateArgumentList::CreateCopy(Context, {ExtArg, BaseArg});
    auto Spec = BuildClassSpecialization(Data.Impl, TemplateArgs->asArray());
    auto SpecTy = GetClassSpecializationType(Spec);

    // Complete base type when needed.
    if (auto BaseSpec = dyn_cast<ClassTemplateSpecializationDecl>(Base)) {
      if (!ForceCompleteClassSpecialization(BaseSpec)) {
        return false;
      }
    }

    // Get type.
    auto NNS = NestedNameSpecifier::Create(Context, nullptr, Data.NS);
    auto SpecElaborated =
        Context.getElaboratedType(ElaboratedTypeKeyword::ETK_None, NNS, SpecTy);
    auto SpecInfo =
        Context.getTrivialTypeSourceInfo(SpecElaborated, E->getLocation());

    // Inherit base.
    auto Specifier = S.CheckBaseSpecifier(E, SourceRange(), false,
                                          AccessSpecifier::AS_public, SpecInfo,
                                          SourceLocation());

    if (Specifier && !S.AttachBaseSpecifiers(E, {Specifier}) &&
        InsertFriend(Base, E) && InsertFriend(E, Spec)) {
      return B;
    }
  }

  return nullptr;
}

Expr *SemaExtension::GetDecoratorMember(
    CXXRecordDecl *E, const DeclarationNameInfo &DNI,
    SourceLocation TemplateKWLoc,
    const TemplateArgumentListInfo *TemplateArgs) {
  auto Base = E->getExtensionBase();

  if (!Base) {
    // Handle uninstantiated dependent bases.
    auto TD = CastTypeToTemplateClass(E->getExtensionBaseLoc()->getType());
    return TD ? BuildDependantRef(BuildRecordQualifier(TD->getTemplatedDecl()),
                                  TemplateKWLoc, DNI, TemplateArgs, true)
              : nullptr;
  }

  return GetBaseExpr(Base, DNI);
}

bool SemaExtension::HandleDecoratorInstantiation(FunctionDecl *D) {
  auto TD = D->getTemplateInstantiationPattern();
  assert(TD && "No template?");
  auto I = DeferredDecorators.find(TD);

  if (I != DeferredDecorators.end()) {
    if (auto Base = FindBaseOfDecorator(D, I->second)) {
      D->setDecoratorBase(Base);
      DeferredDecorators.erase(I);
      return true;
    }
  }

  return false;
}

bool SemaExtension::HandleExtensionInstantiation(ClassTemplateSpecializationDecl *Spec) {
  auto TD = Spec->getSpecializedTemplate();
  assert(TD && "No template?");
  auto I = DeferredExtensions.find(TD);

  if (I != DeferredExtensions.end()) {
    if (auto Base = AttachExtensionBase(Spec, I->second)) {
      Spec->setExtensionBaseLoc(Base);
      return true;
    }
  }

  return false;
}

bool SemaExtension::isMLNamespace(const DeclContext *DC) {
  if (!DC) {
    return false;
  }

  if (auto ND = dyn_cast<NamespaceDecl>(DC)) {
    if (!ND->isInline() &&
        DC->getParent()->getRedeclContext()->isTranslationUnit()) {
      const IdentifierInfo *II = ND->getIdentifier();
      return II && II->isStr("mlrt");
    }
  }

  return isMLNamespace(DC->getParent());
}

bool SemaExtension::isInMLNamespace(const Decl *D) {
  return D ? isMLNamespace(D->getDeclContext()) : false;
}

NestedNameSpecifierLoc SemaExtension::BuildRecordQualifier(RecordDecl *R,
                                                           SourceRange Range) {
  NestedNameSpecifierLocBuilder Builder;

  auto NNS = NestedNameSpecifier::Create(
      S.Context, nullptr, false, S.Context.getRecordType(R).getTypePtr());

  Builder.MakeTrivial(S.Context, NNS, Range);
  return Builder.getWithLocInContext(S.Context);
}

UnaryOperator *SemaExtension::BuildAddrOf(Expr *E, SourceLocation Loc) {
  auto UO = S.CreateBuiltinUnaryOp(Loc, UnaryOperatorKind::UO_AddrOf, E);
  return UO.isUsable() ? cast<UnaryOperator>(UO.get()) : nullptr;
}

Expr *SemaExtension::BuildDeclRef(ValueDecl *V, QualType T,
                                  const DeclarationNameInfo &DNI,
                                  NestedNameSpecifierLoc NNSLoc, bool AddrOf,
                                  SourceLocation Loc) {
  auto DRE = S.BuildDeclRefExpr(V, T, ExprValueKind::VK_PRValue, DNI, NNSLoc);

  if (DRE && AddrOf) {
    return BuildAddrOf(DRE, Loc);
  }

  return DRE;
}

Expr *
SemaExtension::BuildDependantRef(NestedNameSpecifierLoc NNSLoc,
                                 SourceLocation TemplateKWLoc,
                                 const DeclarationNameInfo &DNI,
                                 const TemplateArgumentListInfo *TemplateArgs,
                                 bool AddrOf, SourceLocation Loc) {
  auto E = NNSLoc ? DependentScopeDeclRefExpr::Create(
                        S.Context, NNSLoc, TemplateKWLoc, DNI, TemplateArgs)
                  : nullptr;

  if (E && AddrOf) {
    return BuildAddrOf(E, Loc);
  }

  return E;
}

Expr *SemaExtension::BuildLookup(CXXRecordDecl *NamingClass,
                                 NestedNameSpecifierLoc NNSLoc,
                                 const DeclarationNameInfo &DNI,
                                 const UnresolvedSetImpl &Fns, bool AddrOf,
                                 SourceLocation Loc) {
  auto ULE = S.CreateUnresolvedLookupExpr(NamingClass, NNSLoc, DNI, Fns, false);
  auto E = ULE.isUsable() ? ULE.get() : nullptr;

  if (E && AddrOf) {
    return BuildAddrOf(E, Loc);
  }

  return E;
}

ClassTemplateSpecializationDecl *
SemaExtension::BuildClassSpecialization(ClassTemplateDecl *CTD,
                                        llvm::ArrayRef<TemplateArgument> Args) {
  void *IP = nullptr;

  if (!CTD || Args.empty()) {
    return nullptr;
  }

  auto Spec = CTD->findSpecialization(Args, IP);

  if (!Spec) {
    Spec = ClassTemplateSpecializationDecl::Create(
        S.Context, CTD->getTemplatedDecl()->getTagKind(), CTD->getDeclContext(),
        CTD->getTemplatedDecl()->getBeginLoc(), CTD->getLocation(), CTD, Args,
        nullptr);
    CTD->AddSpecialization(Spec, IP);
  }

  return Spec;
}

QualType SemaExtension::GetClassSpecializationType(
    ClassTemplateSpecializationDecl *Spec) {
  if (Spec) {
    return S.Context.getTemplateSpecializationType(
        TemplateName(Spec->getSpecializedTemplate()),
        Spec->getTemplateArgs().asArray(), S.Context.getRecordType(Spec));
  }

  return QualType();
}

bool SemaExtension::ForceCompleteClassSpecialization(
    ClassTemplateSpecializationDecl *Spec) {

  auto T = GetClassSpecializationType(Spec);
  return !T.isNull() ? S.isCompleteType(Spec->getLocation(), T) : false;
}

bool SemaExtension::ForceCompleteFunction(FunctionDecl *FD) {
  llvm::SmallPtrSet<const Type *, 4> Types;

  Types.insert(FD->getReturnType().getTypePtr());

  for (auto P : FD->parameters()) {
    Types.insert(P->getOriginalType().getTypePtr());
  }

  for (auto Ty : Types) {
    assert(Ty && "Type was nullptr!");
    if (auto TST = Ty->getAs<TemplateSpecializationType>()) {
      auto Spec = cast<ClassTemplateSpecializationDecl>(Ty->getAsRecordDecl());
      if (!ForceCompleteClassSpecialization(Spec)) {
        return false;
      }
    }
  }

  return true;
}

bool SemaExtension::InsertFriend(CXXRecordDecl *Base, CXXRecordDecl *Friend) {


  auto Ty = S.Context.CreateTypeSourceInfo(S.Context.getRecordType(Friend));

  if (Ty) {
    Ty->getTypeLoc().initialize(S.Context, SourceLocation());

    return FriendDecl::Create(S.Context, Base, Base->getLocation(),
                              FriendDecl::FriendUnion(Ty), SourceLocation());
  }

  return false;
}

//===-----------------------------------------------------------------------===//
// Attribute Handlers
//===-----------------------------------------------------------------------===//

void clang::handleLinkNameAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  StringRef Symbol;

  // Get symbol.
  if (AL.isArgExpr(0) && AL.getArgAsExpr(0) &&
      !S.checkStringLiteralArgumentAttr(AL, 0, Symbol))
    return;

  // Check symbol.
  if (Symbol.empty()) {
    S.Diag(AL.getLoc(), diag::err_invalid_link_name);
    return;
  }

  for (auto c : Symbol) {
    if (c == '\0') {
      S.Diag(AL.getLoc(), diag::err_invalid_link_name);
      return;
    }
  }

  // Add attribute.
  D->addAttr(::new (S.Context) LinkNameAttr(S.Context, AL, Symbol));
}

void clang::handleDynamicLinkageAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  StringRef MID;

  // Prevent dynamic methods.
  if (auto const M = dyn_cast<CXXMethodDecl>(D)) {
    S.Diag(AL.getLoc(), diag::err_dynamic_method);
    S.Diag(AL.getLoc(), diag::note_dynamic_mark_record)
        << M->getParent()->getKindName();
    return;
  }

  if (auto const FD = dyn_cast<FunctionDecl>(D)) {
    // Prevent entrypoint.
    if (FD->isMain()) {
      S.Diag(AL.getLoc(), diag::err_dynamic_main);
      return;
    }

    // Prevent decorators.
    if (FD->isDecorator()) {
      S.Diag(AL.getLoc(), diag::err_dynamic_decorator);
      return;
    }
  }

  // Get MID.
  if (AL.isArgExpr(0) && AL.getArgAsExpr(0) &&
      !S.checkStringLiteralArgumentAttr(AL, 0, MID))
    return;

  // Add attribute.
  D->addAttr(::new (S.Context) DynamicLinkageAttr(S.Context, AL, MID));
}

void clang::handleDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  auto FD = cast<FunctionDecl>(D);
  auto E = AL.getArgAsExpr(0u);
  assert(E && "No argument?");

  // A decorator can only target one function.
  if (FD->hasAttr<DecoratorAttr>()) {
    S.Diag(AL.getLoc(), diag::err_decorator_one_target);
    return;
  }

  // Prevent setting entrypoint as decorator.
  if (FD->isMain()) {
    S.Diag(AL.getLoc(), diag::err_decorator_main);
    return;
  }

  // Prevent dynamic decorator.
  if (FD->hasDynamicLinkage()) {
    S.Diag(AL.getLoc(), diag::err_decorator_dynamic);
    return;
  }

  // Add attribute.
  D->addAttr(::new (S.Context) DecoratorAttr(
      S.Context, AL, S.MLExt.FindBaseOfDecorator(FD, E)));
}

void clang::handleTailDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  TypeSourceInfo *TSI = nullptr;
  auto FD = cast<FunctionDecl>(D);

  // Check if already marked.
  if (FD->isTailDecorator()) {
    S.Diag(AL.getLoc(), diag::err_tail_already_marked)
        << FD->isCXXClassMember();
    return;
  }

  // Check if already declared as decorator.
  if (FD->isDecorator()) {
    S.Diag(AL.getLoc(), diag::err_tail_is_decorator);
    return;
  }

  if (AL.hasParsedType()) {
    auto T = S.GetTypeFromParser(AL.getTypeArg(), &TSI);

    if (!TSI) {
      TSI = S.Context.getTrivialTypeSourceInfo(T, AL.getLoc());
    }

    assert(TSI && "Type was nullptr!");
  }

  // Add attribute.
  D->addAttr(::new (S.Context) TailDecoratorAttr(S.Context, AL, TSI));
}

void clang::handleOptionalDecoratorAttr(Sema &S, Decl *D,
                                        const ParsedAttr &AL) {
  D->addAttr(::new (S.Context) OptionalDecoratorAttr(S.Context, AL));
}

void clang::handleLockingDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  D->addAttr(::new (S.Context) LockingDecoratorAttr(S.Context, AL));
}

void clang::handleRecordExtensionAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  TypeSourceInfo *TSI = nullptr;
  auto E = cast<CXXRecordDecl>(D);
  assert(AL.hasParsedType() && "No type?");

  // Get base type.
  auto T = S.GetTypeFromParser(AL.getTypeArg(), &TSI);

  if (!TSI) {
    TSI = S.Context.getTrivialTypeSourceInfo(T, AL.getLoc());
  }

  assert(TSI && "Type was nullptr!");

  // TODO: we avoid template bases for now.
  if (T->isDependentType()) {
    S.Diag(AL.getLoc(), diag::err_decorator_argument_not_valid);
    return;
  }

  // Add attribute.
  if (auto BaseType = S.MLExt.AttachExtensionBase(E, TSI)) {
    D->addAttr(::new (S.Context) RecordExtensionAttr(S.Context, AL, BaseType));
  } else {
    S.Diag(AL.getLoc(), diag::err_extension_failed);
  }
}