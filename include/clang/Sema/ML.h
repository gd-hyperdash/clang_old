//===- ML.h - Sema ML extensions ---------------------------------*- C++ -*-===//
//
// See ML_LICENSE.txt for license information.
//
//===-----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_SEMA_ML_H
#define LLVM_CLANG_SEMA_ML_H

#include "clang/Sema/MLTemplate.h"

namespace clang {
class LookupResult;
class ParsedAttr;

/// Provides custom Sema utilities.
class SemaML {
  friend class Sema;
  friend class SemaMLTemplate;

  enum DecoratorBaseKind {
    Unknown,
    Simple,         // we have one well defined candidate
    Lookup,         // we have multiple candidates
    ClassDependant, // the base depends on a templated class
  };

public:
  Sema &S;
  SemaMLTemplate MLT;

  /// Set to true when a decorator attribute is being parsed.
  /// This affects the parser, and enables method decoration
  /// by using the name only.
  bool HandlingDecoratorAttr;

  /// Set to true when a dtor decorator is being parsed or
  /// constructed. This affects the parser, enabling the '~'
  /// syntax.
  bool HandlingDtor;

protected:
  /// Cache for "link_name", used to prevent defining the
  /// same symbol more than once.
  llvm::SetVector<StringRef> LinkNameCache;

  /// List of name info used in instantiation.
  llvm::SmallVector<DeclarationNameInfo, 8u> DeferredDNI;

  SemaML(Sema &SemaRef)
      : S(SemaRef), MLT(SemaRef, *this), HandlingDecoratorAttr(false),
        HandlingDtor(false) {}

public:
  void cacheLinkName(StringRef S) { LinkNameCache.insert(S); }
  bool hasLinkNameCached(StringRef S) { return LinkNameCache.contains(S); }

  /// Check if this declaration is under the ML namespace.
  bool isMLNamespace(const DeclContext *DC);
  bool isInMLNamespace(const Decl *D);

  std::uint64_t DeferDecoratorDtor();
  bool IsDeferredDecoratorDtor(const std::uint64_t Value);

  std::uint64_t DeferDecoratorDNI(const DeclarationNameInfo &DNI);
  DeclarationNameInfo GetDecoratorDNI(const std::uint64_t Value);

  Expr *LookupDecoratorBaseImpl(CXXRecordDecl *Base, LookupResult &R);

  Expr *LookupDecoratorMemberBase(CXXRecordDecl *Base,
                                  const DeclarationNameInfo &DNI);

  Expr *LookupDecoratorDtorBase(CXXRecordDecl *Base);

  /// When handing extensions, find the correct decorator base.
  Expr *
  GetDecoratorMemberBaseExpr(CXXRecordDecl *E, const DeclarationNameInfo &DNI,
                             SourceLocation TemplateKWLoc,
                             const TemplateArgumentListInfo *TemplateArgs);

  /// What kind of base does this expression hold?
  DecoratorBaseKind GetDecoratorBaseKind(Expr *BaseExpr);

  FunctionDecl *HandleSimpleBase(FunctionDecl *D, Expr *BaseExpr);
  FunctionDecl *HandleLookupBase(FunctionDecl *D, Expr *BaseExpr,
                                 CXXRecordDecl *ClassBase);
  FunctionDecl *HandleDependantBase(FunctionDecl *D, Expr *BaseExpr,
                                    CXXRecordDecl *ClassBase);

  FunctionDecl *ValidateDecoratorBase(FunctionDecl *D, FunctionDecl *B);

  FunctionDecl *FindBaseOfDecorator(FunctionDecl *FD, Expr *E);
  TypeSourceInfo *AttachBaseToExtension(CXXRecordDecl *E, TypeSourceInfo *B);
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