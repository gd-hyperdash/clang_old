//===------------- SemaMLTemplate.cpp - Sema ML template extensions --------===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

#include "clang/Sema/MLTemplate.h"
#include "clang/Sema/SemaInternal.h"
#include "clang/Sema/Template.h"

using namespace clang;

//===-----------------------------------------------------------------------===//
// Helpers
//===-----------------------------------------------------------------------===//

static bool ExtensionHasCtor(CXXRecordDecl *E) {
  for (auto D : E->decls()) {
    if (auto Ctor = dyn_cast<CXXConstructorDecl>(D)) {
      auto const T = Ctor->getType().getAsString();
      if (T == "void (mlrt::ext_init_t)") {
        return true;
      }
    }
  }

  return false;
}

static ClassTemplateSpecializationDecl *GetExtensionImpl(CXXRecordDecl *E) {
  auto BaseSpec = E->bases_begin();
  assert(BaseSpec && "No base?");
  auto Base = BaseSpec->getType()->getAsCXXRecordDecl();
  assert(Base && "No base?");
  assert(Base->getQualifiedNameAsString() == "mlrt::MLExtensionImpl" &&
         "Invalid base!");
  return cast<ClassTemplateSpecializationDecl>(Base);
}

static CXXMethodDecl *GetDtorDecorator(CXXRecordDecl *Impl) {
  for (auto M : Impl->methods()) {
    if (M->getName() == "deleteExtData") {
      return M;
    }
  }

  llvm_unreachable("Could not find the destructor decorator!");
  return nullptr;
}

//===-----------------------------------------------------------------------===//
// SemaMLTemplate
//===-----------------------------------------------------------------------===//

void SemaMLTemplate::FinalizeExtensionInstantiation(
    ClassTemplateSpecializationDecl *Spec) {
  // Complete implementation.
  auto ExtImpl = GetExtensionImpl(Spec);
  ExtImpl->setExtensionBaseLoc(Spec->getExtensionBaseLoc());

  // Handle dtor decorator.
  auto Dtor = Spec->getExtensionBase()->getDestructor();

  if (Dtor && ExtensionHasCtor(Spec)) {
    auto DtorDeco = GetDtorDecorator(ExtImpl);

    if (ForceCompleteFunction(DtorDeco)) {
      DtorDeco->setDecoratorBase(Dtor);
      S.InstantiateFunctionDefinition(DtorDeco->getLocation(), DtorDeco, true,
                                      true);
    }
  }

  // Handle extension decorators.
  for (auto M : Spec->methods()) {
    if (M->isDecorator()) {
      HandleDecoratorInstantiation(M);
      S.InstantiateFunctionDefinition(M->getLocation(), M, true, true);
    }
  }
}

bool SemaMLTemplate::ForceCompleteFunction(FunctionDecl *FD) {
  llvm::SmallPtrSet<const Type *, 4> Types;

  Types.insert(FD->getReturnType().getTypePtr());

  for (auto P : FD->parameters()) {
    Types.insert(P->getOriginalType().getTypePtr());
  }

  for (auto Ty : Types) {
    assert(Ty && "Type was nullptr!");
    if (auto TST = Ty->getAs<TemplateSpecializationType>()) {
      auto Spec = cast<ClassTemplateSpecializationDecl>(Ty->getAsRecordDecl());
      if (!ForceCompleteClassTS(Spec)) {
        return false;
      }
    }
  }

  return true;
}

ClassTemplateSpecializationDecl *
SemaMLTemplate::CreateClassTS(ClassTemplateDecl *CTD,
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

ClassTemplateSpecializationDecl *SemaMLTemplate::GetClassTS(CXXRecordDecl *R) {
  return dyn_cast<ClassTemplateSpecializationDecl>(R);
}

QualType SemaMLTemplate::GetClassTSType(ClassTemplateSpecializationDecl *Spec) {
  if (Spec) {
    return S.Context.getTemplateSpecializationType(
        TemplateName(Spec->getSpecializedTemplate()),
        Spec->getTemplateArgs().asArray(), S.Context.getRecordType(Spec));
  }

  return QualType();
}

bool SemaMLTemplate::ForceCompleteClassTS(
    ClassTemplateSpecializationDecl *Spec) {
  auto T = GetClassTSType(Spec);
  return !T.isNull() ? S.isCompleteType(Spec->getLocation(), T) : false;
}

QualType SemaMLTemplate::GetExtensionBaseType(CXXRecordDecl *E,
                                              TypeSourceInfo *B) {
  QualType BaseType = B->getType();

  // Handle dependant base.
  if (!BaseType.isNull() && BaseType->isDependentType()) {
    auto Args = S.getTemplateInstantiationArgs(E);

    if (auto TPT = BaseType->getAs<TemplateTypeParmType>()) {
      auto &Arg = Args(TPT->getDepth(), TPT->getIndex());
      BaseType = Arg.getAsType();
    }

    if (auto TST = BaseType->getAs<TemplateSpecializationType>()) {
      TST->dump();
      llvm_unreachable("BP");
    }
  }

  return BaseType;
}

bool SemaMLTemplate::DeferDecoratorBaseLookup(FunctionDecl *D, Expr *BaseExpr) {
  assert(D && "Decorator was nullptr!");
  assert(BaseExpr && "Base was nullptr!");

  if (D->isTemplated() && !D->isTemplateInstantiation()) {
    DeferredDecorators.insert({D, BaseExpr});
    return true;
  }

  return false;
}

bool SemaMLTemplate::DeferExtensionBaseLookup(CXXRecordDecl *E,
                                              TypeSourceInfo *BaseType) {
  if (E->isTemplated() &&
      !isTemplateInstantiation(E->getTemplateSpecializationKind())) {
    auto TD = E->getDescribedClassTemplate();
    assert(TD && "No template?");
    DeferredExtensions.insert({TD, BaseType});
    return BaseType;
  }

  return false;
}

void SemaMLTemplate::HandleDecoratorInstantiation(FunctionDecl *D) {
  auto TD = D->getTemplateInstantiationPattern();
  assert(TD && "No template?");

  // Make fure the type is complete.
  if (!ForceCompleteFunction(D)) {
    return;
  }

  auto I = DeferredDecorators.find(TD);

  if (I == DeferredDecorators.end()) {
    return;
  }

  D->setDecoratorBase(ML.FindBaseOfDecorator(D, I->second));
}

void SemaMLTemplate::HandleExtensionInstantiation(
    ClassTemplateSpecializationDecl *Spec) {
  auto TD = Spec->getSpecializedTemplate();
  assert(TD && "No template?");

  // Make sure the type is complete.
  if (!ForceCompleteClassTS(Spec)) {
    return;
  }

  auto I = DeferredExtensions.find(TD);

  if (I == DeferredExtensions.end()) {
    return;
  }

  auto BaseLoc = ML.AttachBaseToExtension(Spec, I->second);

  if (BaseLoc) {
    Spec->setExtensionBaseLoc(BaseLoc);
    FinalizeExtensionInstantiation(Spec);
  }
}