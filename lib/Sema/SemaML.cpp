//===--------------------- SemaML.cpp - Sema ML extensions  ----------------===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

#include "clang/AST/DeclFriend.h"
#include "clang/Sema/ML.h"
#include "clang/Sema/SemaInternal.h"
#include "clang/Sema/SemaDiagnostic.h"
#include "clang/Sema/Template.h"

using namespace clang;

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

NestedNameSpecifierLoc BuildRecordQualifier(Sema &S, RecordDecl *R,
                                            SourceRange Range = SourceRange()) {
  NestedNameSpecifierLocBuilder Builder;
  auto &Context = S.Context;

  auto NNS = NestedNameSpecifier::Create(Context, nullptr, false,
                                         Context.getRecordType(R).getTypePtr());

  Builder.MakeTrivial(Context, NNS, Range);
  return Builder.getWithLocInContext(Context);
}

UnaryOperator *BuildAddrOf(Sema &S, Expr *E,
                           SourceLocation Loc = SourceLocation()) {
  if (E) {
    auto UO = S.CreateBuiltinUnaryOp(Loc, UnaryOperatorKind::UO_AddrOf, E);
    return UO.isUsable() ? cast<UnaryOperator>(UO.get()) : nullptr;
  }

  return nullptr;
}

bool InsertFriend(Sema &S, CXXRecordDecl *Base, CXXRecordDecl *Friend) {
  auto Ty = S.Context.getTrivialTypeSourceInfo(S.Context.getRecordType(Friend));

  if (Ty) {
    return FriendDecl::Create(S.Context, Base, Base->getLocation(),
                              FriendDecl::FriendUnion(Ty), SourceLocation());
  }

  return false;
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

// TODO: There's probably a better way to do this
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
// SemaML
//===-----------------------------------------------------------------------===//

bool SemaML::isMLNamespace(const DeclContext *DC) {
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

bool SemaML::isInMLNamespace(const Decl *D) {
  return D ? isMLNamespace(D->getDeclContext()) : false;
}

std::uint64_t SemaML::DeferDecoratorDtor() {
  return static_cast<std::uint64_t>(1ull << 63);
}

bool SemaML::IsDeferredDecoratorDtor(const std::uint64_t Value) {
  return static_cast<bool>((Value >> 63) & 1);
}

std::uint64_t SemaML::DeferDecoratorDNI(const DeclarationNameInfo &DNI) {
  DeferredDNI.push_back(DNI);
  return DeferredDNI.size() - 1u;
}

DeclarationNameInfo SemaML::GetDecoratorDNI(const std::uint64_t Value) {
  assert(!IsDeferredDecoratorDtor(Value) && Value < DeferredDNI.size() &&
         "Invalid value!");
  return DeferredDNI[Value];
}

Expr *SemaML::LookupDecoratorBaseImpl(CXXRecordDecl *Base, LookupResult &R) {
  DeclarationNameInfo DNI = R.getLookupNameInfo();

  // If the base is a specialization, make sure it's fully instantiated.
  if (auto Spec = MLT.GetClassTS(Base)) {
    if (!MLT.ForceCompleteClassTS(Spec)) {
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
    auto Q = BuildRecordQualifier(S, Base);

    // Build expression.
    if (Unresolved.size() == 1u) {
      auto DeclRef = S.BuildDeclRefExpr(
          M, M->getType(), ExprValueKind::VK_PRValue, M->getNameInfo(), Q);
      return BuildAddrOf(S, DeclRef, DNI.getLoc());
    } else {
      auto ULE = S.CreateUnresolvedLookupExpr(Base, Q, DNI, Unresolved, false);

      if (ULE.isUsable()) {
        return BuildAddrOf(S, ULE.get(), DNI.getLoc());
      }
    }
  }

  return nullptr;
}

Expr *SemaML::LookupDecoratorMemberBase(CXXRecordDecl *Base,
                                   const DeclarationNameInfo &DNI) {
  LookupResult R(S, DNI, Sema::LookupNameKind::LookupMemberName);
  return LookupDecoratorBaseImpl(Base, R);
}

Expr *SemaML::LookupDecoratorDtorBase(CXXRecordDecl *Base) {
  if (auto Dtor = Base->getDestructor()) {
    LookupResult R(S, Dtor->getNameInfo(),
                   Sema::LookupNameKind::LookupDestructorName);
    return LookupDecoratorBaseImpl(Base, R);
  }

  return nullptr;
}

Expr *SemaML::GetDecoratorMemberBaseExpr(
    CXXRecordDecl *E, const DeclarationNameInfo &DNI,
    SourceLocation TemplateKWLoc,
    const TemplateArgumentListInfo *TemplateArgs) {
  auto Base = E->getExtensionBase();

  if (!Base) {
    // Handle uninstantiated dependent bases.
    return IntegerLiteral::Create(
        S.Context,
        llvm::APInt(64u, HandlingDtor ? DeferDecoratorDtor()
                                      : DeferDecoratorDNI(DNI)),
        S.Context.LongLongTy, SourceLocation());
  }

  return HandlingDtor ? LookupDecoratorDtorBase(Base)
                      : LookupDecoratorMemberBase(Base, DNI);
}

SemaML::DecoratorBaseKind SemaML::GetDecoratorBaseKind(Expr *BaseExpr) {
  if (isa<DeclRefExpr>(BaseExpr)) {
    return DecoratorBaseKind::Simple;
  }

  if (isa<UnresolvedLookupExpr>(BaseExpr)) {
    return DecoratorBaseKind::Lookup;
  }

  if (isa<IntegerLiteral>(BaseExpr)) {
    return DecoratorBaseKind::ClassDependant;
  }

  return DecoratorBaseKind::Unknown;
}

 FunctionDecl *SemaML::HandleSimpleBase(FunctionDecl *D, Expr *BaseExpr) {
  FunctionDecl *FD = nullptr;
  auto DRE = cast<DeclRefExpr>(BaseExpr);
  bool SkipTypeCheck = D->isTailDecorator();

  if (auto Fn = dyn_cast<FunctionDecl>(DRE->getDecl())) {
    FD = Fn;
  } else if (auto TPD = dyn_cast<NonTypeTemplateParmDecl>(DRE->getDecl())) {
    auto Args = S.getTemplateInstantiationArgs(D);
    auto &Arg = Args(TPD->getDepth(), TPD->getIndex());
    FD = cast<FunctionDecl>(Arg.getAsDecl());
  }

  if (!FD) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_not_valid);
    return nullptr;
  }

  // TODO: checking types with strings? /srs?
  if (!SkipTypeCheck &&
      D->getType().getAsString() != FD->getType().getAsString()) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_type_mismatch)
        << FD->getQualifiedNameAsString();
    return nullptr;
  }

  return FD;
}

FunctionDecl *SemaML::HandleLookupBase(FunctionDecl *D, Expr *BaseExpr,
                                       CXXRecordDecl *ClassBase) {
  FunctionDecl *FD = nullptr;
  auto ULE = cast<UnresolvedLookupExpr>(BaseExpr);

  if (ULE->hasExplicitTemplateArgs()) {
    FD = S.ResolveSingleFunctionTemplateSpecialization(ULE, true);
  } else {
    DeclAccessPair P;
    auto DT = GetDecoratorType(S, D, ClassBase);

    if (!DT.isNull()) {
      FD = S.ResolveAddressOfOverloadedFunction(BaseExpr, DT, true, P);
    }
  }

  if (!FD) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_not_valid);

    if (ULE->getType() == S.Context.OverloadTy) {
      S.NoteAllOverloadCandidates(BaseExpr);
    }
  }

  return FD;
}

FunctionDecl *SemaML::HandleDependantBase(FunctionDecl *D, Expr *BaseExpr,
                                          CXXRecordDecl *ClassBase) {
  assert(ClassBase && "Base was nullptr!");
  Expr *DepExpr = nullptr;
  auto IL = cast<IntegerLiteral>(BaseExpr);
  auto ID = IL->getValue().getZExtValue();

  if (IsDeferredDecoratorDtor(ID)) {
    DepExpr = LookupDecoratorDtorBase(ClassBase);
  } else {
    DepExpr = LookupDecoratorMemberBase(ClassBase, GetDecoratorDNI(ID));
  }

  if (DepExpr) {
    auto UnwrappedDepExpr = UnwrapDecoratorExpr(DepExpr);

    switch (GetDecoratorBaseKind(UnwrappedDepExpr)) {
    case DecoratorBaseKind::Simple:
      return HandleSimpleBase(D, UnwrappedDepExpr);
      break;
    case DecoratorBaseKind::Lookup:
      return HandleLookupBase(D, DepExpr, ClassBase);
      break;
    default:;
    }
  }

  S.Diag(D->getLocation(), diag::err_decorator_argument_not_valid);
  return nullptr;
}

FunctionDecl *SemaML::ValidateDecoratorBase(FunctionDecl *D, FunctionDecl *B) {
  if (!D || !B) {
    return nullptr;
  }

  // Instantiate base if required.
  if (auto Templ = B->getPrimaryTemplate()) {
    auto Args = D->getTemplateSpecializationArgs();
    assert(Args && "No args?");
    B = S.InstantiateFunctionDeclaration(Templ, Args, B->getLocation());

    if (!B) {
      S.Diag(D->getLocation(), diag::err_decorator_argument_not_valid);
      return nullptr;
    }
  }

  // Decorators cannot decorate other decorators.
  if (B->isDecorator()) {
    S.Diag(D->getLocation(), diag::err_decorator_argument_is_decorator);
    return nullptr;
  }

  if (auto BaseMethod = dyn_cast<CXXMethodDecl>(B)) {
    auto DecoMethod = dyn_cast<CXXMethodDecl>(D);
    auto DecoParent = DecoMethod ? DecoMethod->getParent() : nullptr;

    // Methods can only be decorated in the context of an extension.
    if (!DecoMethod || !DecoParent->isRecordExtension()) {
      S.Diag(D->getLocation(), diag::err_decorator_argument_not_valid);
      return nullptr;
    }

    // Method base and extension base must match.
    auto ExtBase = DecoParent->getExtensionBase();
    assert(ExtBase && "No base?");

    if (ExtBase != BaseMethod->getParent()) {
      S.Diag(D->getLocation(), diag::err_decorator_argument_type_mismatch)
          << B->getQualifiedNameAsString();
      return nullptr;
    }
  }

  // Complete base type when needed.
  if (!MLT.ForceCompleteFunction(B)) {
    S.Diag(B->getLocation(), diag::err_decorator_argument_not_valid);
    return nullptr;
  }

  return B;
}

FunctionDecl *SemaML::FindBaseOfDecorator(FunctionDecl *D, Expr *BaseExpr) {
  FunctionDecl *FD = nullptr;
  CXXRecordDecl *ClassBase = nullptr;

  // Skip deferred decorator.
  if (MLT.DeferDecoratorBaseLookup(D, BaseExpr)) {
    return nullptr;
  }

  // Unwrap the expression.
  auto UnwrappedExpr = UnwrapDecoratorExpr(BaseExpr);

  // Get base, if any.
  if (auto M = dyn_cast<CXXMethodDecl>(D)) {
    auto P = M->getParent();

    if (P->isRecordExtension()) {
      ClassBase = P->getExtensionBase();
    }
  }

  // Handle base.
  switch (GetDecoratorBaseKind(UnwrappedExpr)) {
  case DecoratorBaseKind::Simple:
    FD = HandleSimpleBase(D, UnwrappedExpr);
    break;
  case DecoratorBaseKind::Lookup:
    FD = HandleLookupBase(D, BaseExpr, ClassBase);
    break;
  case DecoratorBaseKind::ClassDependant:
    FD = HandleDependantBase(D, UnwrappedExpr, ClassBase);
    break;
  default:;
  }

  return ValidateDecoratorBase(D, FD);
}

TypeSourceInfo *SemaML::AttachBaseToExtension(CXXRecordDecl *E,
                                              TypeSourceInfo *B) {
  auto &Context = S.Context;
  auto TU = Context.getTranslationUnitDecl();

  // Skip deferred extension.
  if (MLT.DeferExtensionBaseLookup(E, B)) {
    return B;
  }

  auto Data = FindExtensionImpl(TU);

  if (!Data) {
    return nullptr;
  }

  // Get base.
  QualType BaseType = MLT.GetExtensionBaseType(E, B);
  assert(!BaseType.isNull() && "No type?");
  auto Base = BaseType->getAsCXXRecordDecl();
  assert(Base && "Base was nullptr!");

  // If the base is a specialization, make sure it's fully instantiated.
  if (auto Spec = MLT.GetClassTS(Base)) {
    if (!MLT.ForceCompleteClassTS(Spec)) {
      return nullptr;
    }
  }

  // Instantiate ML base.
  TemplateArgument ExtArg(Context.getRecordType(E));
  TemplateArgument BaseArg(BaseType.getCanonicalType());
  auto TemplateArgs =
      TemplateArgumentList::CreateCopy(Context, {ExtArg, BaseArg});
  auto Spec = MLT.CreateClassTS(Data.Impl, TemplateArgs->asArray());
  auto SpecTy = MLT.GetClassTSType(Spec);

  // Get ML base type.
  auto NNS = NestedNameSpecifier::Create(Context, nullptr, Data.NS);
  auto SpecElaborated =
      Context.getElaboratedType(ElaboratedTypeKeyword::ETK_None, NNS, SpecTy);
  auto SpecInfo =
      Context.getTrivialTypeSourceInfo(SpecElaborated, E->getLocation());

  // Inherit ML base.
  auto Specifier =
      S.CheckBaseSpecifier(E, SourceRange(), false, AccessSpecifier::AS_public,
                           SpecInfo, SourceLocation());

  if (Specifier && !S.AttachBaseSpecifiers(E, {Specifier}) &&
      InsertFriend(S, Base, E) && InsertFriend(S, E, Spec)) {
    return Context.getTrivialTypeSourceInfo(Context.getRecordType(Base));
  }

  return nullptr;
}

//===-----------------------------------------------------------------------===//
// Attribute Handlers
//===-----------------------------------------------------------------------===//

void clang::handleLinkNameAttr(Sema &S, Decl *D, const ParsedAttr &AL) {
  StringRef Symbol;
  auto &SML = S.ML;

  // Get symbol.
  if (AL.isArgExpr(0) && AL.getArgAsExpr(0) &&
      !S.checkStringLiteralArgumentAttr(AL, 0, Symbol))
    return;

  // Check symbol.
  if (Symbol.empty()) {
    S.Diag(AL.getLoc(), diag::err_invalid_link_name);
    return;
  }

  if (SML.hasLinkNameCached(Symbol)) {
    S.Diag(AL.getLoc(), diag::err_link_name_already_defined);
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
  SML.cacheLinkName(Symbol);
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
  auto &SML = S.ML;
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
      S.Context, AL, SML.FindBaseOfDecorator(FD, E)));
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
  auto &SML = S.ML;
  auto E = cast<CXXRecordDecl>(D);
  assert(AL.hasParsedType() && "No type?");

  // Get base type.
  auto T = S.GetTypeFromParser(AL.getTypeArg(), &TSI);

  if (!TSI) {
    TSI = S.Context.getTrivialTypeSourceInfo(T, AL.getLoc());
  }

  assert(TSI && "Type was nullptr!");

  // Add attribute.
  if (auto BaseType = SML.AttachBaseToExtension(E, TSI)) {
    D->addAttr(::new (S.Context) RecordExtensionAttr(S.Context, AL, BaseType));
  } else {
    S.Diag(AL.getLoc(), diag::err_extension_failed);
  }
}