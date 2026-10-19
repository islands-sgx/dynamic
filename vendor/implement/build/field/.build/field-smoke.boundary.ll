; ModuleID = '/home/meandssh/islands-sgx/implement/build/field/.build/field-smoke.opt.ll'
source_filename = "/home/meandssh/islands-sgx/implement/build/field/.build/field-smoke.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@sink = internal global i32 0, align 4
@.str = private unnamed_addr constant [17 x i8] c"atfield.field.v1\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [70 x i8] c"/home/meandssh/islands-sgx/implement/build/field/.build/field-smoke.c\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [{ ptr, ptr, ptr, i32, ptr } { ptr @protected_choice, ptr @.str, ptr @.str.1, i32 5, ptr null }], section "llvm.metadata"

; Function Attrs: nofree noinline norecurse noredzone nounwind memory(readwrite, argmem: none, target_mem0: none, target_mem1: none) uwtable
define dso_local i32 @protected_choice(i32 noundef %0) #0 {
atfield.entry.6864127729266408981:
  call void asm sideeffect ".globl __atfield_field_enter_6864127729266408981\0A.hidden __atfield_field_enter_6864127729266408981\0A__atfield_field_enter_6864127729266408981:\0A", "~{memory},~{dirflag},~{fpsr},~{flags}"() #2
  notail call void @field_enter(i64 6864127729266408981) #2
  br label %atfield.marker.6864127729266408981

1:                                                ; preds = %atfield.body.6864127729266408981
  store volatile i32 20, ptr @sink, align 4, !tbaa !5
  %2 = load volatile i32, ptr @sink, align 4, !tbaa !5
  br label %7

3:                                                ; preds = %atfield.body.6864127729266408981
  %4 = shl nsw i32 %0, 1
  store volatile i32 %4, ptr @sink, align 4, !tbaa !5
  %5 = load volatile i32, ptr @sink, align 4, !tbaa !5
  %6 = add nsw i32 %5, 1
  br label %7

7:                                                ; preds = %3, %1
  %8 = phi i32 [ %2, %1 ], [ %6, %3 ]
  br label %atfield.normal-close.6864127729266408981

atfield.marker.6864127729266408981:               ; preds = %atfield.entry.6864127729266408981
  notail call void @__atfield_marker_6864127729266408981() #2
  br label %atfield.body.6864127729266408981

atfield.body.6864127729266408981:                 ; preds = %atfield.marker.6864127729266408981
  call void asm sideeffect ".globl __atfield_body_6864127729266408981\0A.hidden __atfield_body_6864127729266408981\0A__atfield_body_6864127729266408981:\0A", "~{memory},~{dirflag},~{fpsr},~{flags}"() #2
  %9 = icmp eq i32 %0, 17
  br i1 %9, label %1, label %3

atfield.normal-close.6864127729266408981:         ; preds = %7
  %atfield.return.value = phi i32 [ %8, %7 ]
  call void asm sideeffect ".globl __atfield_normal_close_6864127729266408981\0A.hidden __atfield_normal_close_6864127729266408981\0A__atfield_normal_close_6864127729266408981:\0A", "~{memory},~{dirflag},~{fpsr},~{flags}"() #2
  br label %atfield.field-exit.6864127729266408981

atfield.field-exit.6864127729266408981:           ; preds = %atfield.normal-close.6864127729266408981
  call void asm sideeffect ".globl __atfield_field_exit_6864127729266408981\0A.hidden __atfield_field_exit_6864127729266408981\0A__atfield_field_exit_6864127729266408981:\0A", "~{memory},~{dirflag},~{fpsr},~{flags}"() #2
  notail call void @field_exit(i64 6864127729266408981) #2
  br label %atfield.return.6864127729266408981

atfield.return.6864127729266408981:               ; preds = %atfield.field-exit.6864127729266408981
  ret i32 %atfield.return.value
}

; Function Attrs: nofree norecurse noredzone nounwind memory(readwrite, target_mem0: none, target_mem1: none) uwtable
define dso_local i32 @public_wrapper(i32 noundef %0) local_unnamed_addr #1 {
  %2 = tail call i32 @protected_choice(i32 noundef %0) #3
  ret i32 %2
}

; Function Attrs: nounwind
declare void @field_enter(i64) #2

; Function Attrs: nounwind
declare void @field_exit(i64) #2

; Function Attrs: nounwind
declare hidden void @__atfield_marker_6864127729266408981() #2

attributes #0 = { nofree noinline norecurse noredzone nounwind memory(readwrite, argmem: none, target_mem0: none, target_mem1: none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree norecurse noredzone nounwind memory(readwrite, target_mem0: none, target_mem1: none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind }
attributes #3 = { noredzone }

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
!8 = !{!"Simple C/C++ TBAA"}
