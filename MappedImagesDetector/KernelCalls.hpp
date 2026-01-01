#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern "C"
{
#include "KernelCalls.h"
}