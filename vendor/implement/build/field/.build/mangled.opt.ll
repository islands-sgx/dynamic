; ModuleID = '/home/meandssh/islands-sgx/implement/build/field/.build/mangled.cpp'
source_filename = "/home/meandssh/islands-sgx/implement/build/field/.build/mangled.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [17 x i8] c"atfield.field.v1\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [68 x i8] c"/home/meandssh/islands-sgx/implement/build/field/.build/mangled.cpp\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [{ ptr, ptr, ptr, i32, ptr } { ptr @_ZN7exampleL13protected_cppEi, ptr @.str, ptr @.str.1, i32 2, ptr null }], section "llvm.metadata"

; Function Attrs: mustprogress nofree norecurse noredzone nosync nounwind willreturn memory(none) uwtable
define dso_local noundef range(i32 -2147483647, -2147483648) i32 @_ZN7example6callerEi(i32 noundef %0) local_unnamed_addr #0 {
  %2 = tail call noundef i32 @_ZN7exampleL13protected_cppEi(i32 noundef %0) #2
  ret i32 %2
}

; Function Attrs: mustprogress nofree noinline norecurse noredzone nosync nounwind willreturn memory(none) uwtable
define internal noundef range(i32 -2147483647, -2147483648) i32 @_ZN7exampleL13protected_cppEi(i32 noundef %0) #1 {
  %2 = mul nsw i32 %0, 3
  %3 = add nsw i32 %2, 1
  ret i32 %3
}

attributes #0 = { mustprogress nofree norecurse noredzone nosync nounwind willreturn memory(none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { mustprogress nofree noinline norecurse noredzone nosync nounwind willreturn memory(none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { noredzone }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}
!llvm.errno.tbaa = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{!"clang version 22.1.8"}
!5 = !{!6, !6, i64 0}
!6 = !{!"int", !7, i64 0}
!7 = !{!"omnipotent char", !8, i64 0}
!8 = !{!"Simple C++ TBAA"}
