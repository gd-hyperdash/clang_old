//===- MLTemplate.h - Sema ML template extensions ----------------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_SEMA_ML_TEMPLATE_H
#define LLVM_CLANG_SEMA_ML_TEMPLATE_H

#include "clang/AST/AST.h"

namespace clang {

class TemplateDeclInstantiator;

/// Provides custom Sema template utilities.
class SemaMLTemplate {
  friend class Sema;
  friend class SemaML;

  Sema &S;
  SemaML &ML;

  /// List of incomplete decorators to be instantiated.
  llvm::DenseMap<FunctionDecl *, Expr *> DeferredDecorators;

  /// List of incomplete extensions to be instantiated.
  llvm::DenseMap<ClassTemplateDecl *, TypeSourceInfo *> DeferredExtensions;

  SemaMLTemplate(Sema &SemaRef, SemaML &SemaMLRef)
      : S(SemaRef), ML(SemaMLRef) {}

  void FinalizeExtensionInstantiation(ClassTemplateSpecializationDecl *Spec);

public:
  bool ForceCompleteFunction(FunctionDecl *FD);

  ClassTemplateSpecializationDecl *
  CreateClassTS(ClassTemplateDecl *CTD, llvm::ArrayRef<TemplateArgument> Args);
  ClassTemplateSpecializationDecl *GetClassTS(CXXRecordDecl *R);
  QualType GetClassTSType(ClassTemplateSpecializationDecl *Spec);
  bool ForceCompleteClassTS(ClassTemplateSpecializationDecl *Spec);

  QualType GetExtensionBaseType(CXXRecordDecl *E, TypeSourceInfo *B);

  /// Returns true if the decorator is incomplete.
  bool DeferDecoratorBaseLookup(FunctionDecl *D, Expr *BaseExpr);

  /// Returns true if the extension is incomplete.
  bool DeferExtensionBaseLookup(CXXRecordDecl *E, TypeSourceInfo *BaseType);

  /// Templated decorator instantiation handler.
  void HandleDecoratorInstantiation(FunctionDecl *FD);

  /// Templated extension instantiation handler.
  void HandleExtensionInstantiation(ClassTemplateSpecializationDecl *Spec);
};
} // namespace clang

#endif // LLVM_CLANG_SEMA_ML_TEMPLATE_H