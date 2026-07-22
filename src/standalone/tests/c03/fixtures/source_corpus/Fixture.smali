.class public final Laida/c03/corpus/Fixture;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static add(II)I
    .registers 3
    :try_start
    add-int v0, p0, p1
    :try_end
    return v0
    .catch Ljava/lang/ArithmeticException; {:try_start .. :try_end} :catch_arithmetic

    :catch_arithmetic
    const/4 v0, 0x0
    return v0
.end method

.method public static guardedDivide(II)I
    .registers 3
    if-nez p1, :divide
    new-instance v0, Ljava/lang/ArithmeticException;
    invoke-direct {v0}, Ljava/lang/ArithmeticException;-><init>()V
    throw v0

    :divide
    div-int v0, p0, p1
    return v0
.end method
