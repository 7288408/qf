#include "dobby_internal.h"

#include "Interceptor.h"
#include "InterceptRouting/InterceptRouting.h"
#include "InterceptRouting/Routing/FunctionInlineReplace/function-inline-replace.h"

PUBLIC int DobbyHook(void *address, void *replace_call, void **origin_call) {
  if (!address) {
    ERROR_LOG("函数地址为 0x0");
    return RS_FAILED;
  }

  DLOG(0, "[DobbyHook] Initialize at %p", address);

  // 检查是否已经上钩
  HookEntry *entry = Interceptor::SharedInstance()->FindHookEntry(address);
  if (entry) {
    FunctionInlineReplaceRouting *route = (FunctionInlineReplaceRouting *)entry->route;
    if (route->GetTrampolineTarget() == replace_call) {
      ERROR_LOG("函数 %p 已被钩住.", address);
      return RS_FAILED;
    }
  }

  entry = new HookEntry();
  entry->id = Interceptor::SharedInstance()->GetHookEntryCount();
  entry->type = kFunctionInlineHook;
  entry->function_address = address;

  FunctionInlineReplaceRouting *route = new FunctionInlineReplaceRouting(entry, replace_call);
  route->Prepare();
  route->DispatchRouting();
  Interceptor::SharedInstance()->AddHookEntry(entry);

  // 使用重定位功能设置源调用
  *origin_call = entry->relocated_origin_function;

  // 代码补丁和劫持原始控制流入口
  route->Commit();

  return RS_SUCCESS;
}
