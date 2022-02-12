//===- ML.h - Sema ML extensions ----------------------------------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_SEMA_ML_H
#define LLVM_CLANG_SEMA_ML_H

#include "clang/AST/AST.h"

namespace clang {
class ParsedAttr;

/// Provides custom Sema utilities.
class SemaExtension {
  friend class Sema;

  Sema &S;
  bool DecoContext;
  bool TildeContext;
  llvm::SetVector<StringRef> LinkNameCache;

  llvm::DenseMap<FunctionDecl *, Expr *> DeferredDecorators;
  llvm::DenseMap<ClassTemplateDecl *, TypeSourceInfo *> DeferredExtensions;
  llvm::SmallVector<DeclarationNameInfo, 8u> DeferredDNI;

  SemaExtension(Sema &SemaRef)
      : S(SemaRef), DecoContext(false), TildeContext(false) {}

  Expr *GetBaseExpr(CXXRecordDecl *Base, const DeclarationNameInfo &DNI,
                    bool IsDtor = false);

  Expr *GetBaseExpr(CXXRecordDecl *Base, bool IsDtor) {
    return GetBaseExpr(Base, DeclarationNameInfo(), IsDtor);
  }

public:
  void setDecoratorContext(bool b) { DecoContext = b; }
  bool isDecoratorContext() const { return DecoContext; }

  void setParsingTilde(bool b) { TildeContext = b; }
  bool isParsingTilde() const { return TildeContext; }

  void cacheLinkName(StringRef S) { LinkNameCache.insert(S); }
  bool hasLinkName(StringRef S) { return LinkNameCache.contains(S); }

  /// Functions for handling decorators.

  FunctionDecl *FindBaseOfDecorator(FunctionDecl *FD, Expr *E);
  TypeSourceInfo *AttachExtensionBase(CXXRecordDecl *E, TypeSourceInfo *B);
  std::uint64_t DeferDecoratorDNI(const DeclarationNameInfo &DNI);
  DeclarationNameInfo GetDecoratorDNI(const std::uint64_t Value);
  std::uint64_t DeferDecoratorDtor();
  bool IsDeferredDecoratorDtor(const std::uint64_t Value);
  Expr *GetDecoratorMember(CXXRecordDecl *E, const DeclarationNameInfo &DNI,
                           SourceLocation TemplateKWLoc,
                           const TemplateArgumentListInfo *TemplateArgs);

  /// Functions for handling templates.

  bool HandleDecoratorInstantiation(FunctionDecl *D);
  bool HandleExtensionInstantiation(ClassTemplateSpecializationDecl *Spec);

  /// Generic sema utilities.

  bool isMLNamespace(const DeclContext *DC);
  bool isInMLNamespace(const Decl *D);

  NestedNameSpecifierLoc
  BuildRecordQualifier(RecordDecl *R, SourceRange Range = SourceRange());

  UnaryOperator *BuildAddrOf(Expr *E, SourceLocation Loc = SourceLocation());

  Expr *BuildInteger(std::uint64_t const Value);

  Expr *BuildDeclRef(ValueDecl *V, QualType T, const DeclarationNameInfo &DNI,
                     NestedNameSpecifierLoc NNSLoc, bool AddrOf,
                     SourceLocation Loc = SourceLocation());

  Expr *BuildDependantRef(NestedNameSpecifierLoc NNSLoc,
                          SourceLocation TemplateKWLoc,
                          const DeclarationNameInfo &DNI,
                          const TemplateArgumentListInfo *TemplateArgs,
                          bool AddrOf, SourceLocation Loc = SourceLocation());

  Expr *BuildLookup(CXXRecordDecl *NamingClass, NestedNameSpecifierLoc NNSLoc,
                    const DeclarationNameInfo &DNI,
                    const UnresolvedSetImpl &Fns, bool AddrOf,
                    SourceLocation Loc = SourceLocation());

  ClassTemplateSpecializationDecl *
  BuildClassSpecialization(ClassTemplateDecl *CTD,
                           llvm::ArrayRef<TemplateArgument> Args);

  QualType GetClassSpecializationType(ClassTemplateSpecializationDecl *Spec);
  bool ForceCompleteClassSpecialization(ClassTemplateSpecializationDecl *Spec);

  bool ForceCompleteFunction(FunctionDecl *FD);

  bool InsertFriend(CXXRecordDecl *Base, CXXRecordDecl *Friend);
};

/// Attribute handlers.

void handleLinkNameAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleDynamicLinkageAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleTailDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleOptionalDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleLockingDecoratorAttr(Sema &S, Decl *D, const ParsedAttr &AL);
void handleRecordExtensionAttr(Sema &S, Decl *D, const ParsedAttr &AL);
} // namespace clang

#endif // LLVM_CLANG_SEMA_ML_H