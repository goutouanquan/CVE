# Vulnerability Report

## Summary
- **Title**: IDOR Workspace Isolation Bypass via URL Path Parameter in koalixcrm
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-639 - Authorization Bypass Through User-Controlled Key
- **CVSS 3.1 Score**: 7.1 High (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)
- **Vendor**: KoalixSwitzerland
- **Product**: koalixcrm
- **Repository**: https://github.com/KoalixSwitzerland/koalixcrm

## Description

koalixcrm contains a workspace isolation bypass vulnerability in the `WorkspaceScopedViewSetMixin._resolve_workspace()` method. The method accepts a `workspace_id` from the URL path parameter and looks it up without verifying the authenticated user has access to that workspace.

The `WorkspaceContextMiddleware` correctly resolves and authorizes the workspace for session-based requests. However, when using API token authentication (OIDC), the DRF authentication layer runs after Django middleware. At middleware execution time, `request.user` is still `AnonymousUser`, so `active_workspace` is set to `None`. The viewset then falls back to the unvalidated URL `workspace_id` parameter.

This allows any API-authenticated user to access data in any active workspace by simply changing the `workspace_id` in the URL path, and to create records in arbitrary workspaces via `perform_create()`.

## Affected Component
- File: `koalixcrm/shared/workspace_scoped_view_set.py`
- Function: `_resolve_workspace()`, lines 37-41
- Also: `perform_create()`, line 60-61

## Proof of Concept

```
# User authenticated via OIDC token, belongs to workspace 1
# Accessing workspace 2's data without authorization:
GET /koalixcrm_reporting/api/v1/2/tasks/
Authorization: Bearer <valid_oidc_token>

# Creating a record in workspace 2:
POST /koalixcrm_reporting/api/v1/2/tasks/
Authorization: Bearer <valid_oidc_token>
{"description": "injected task"}
```

## Impact

Any API-authenticated user can read, create, and potentially modify data across all active workspaces, bypassing the multi-tenant isolation model.

## Suggested Fix

Add authorization check in `_resolve_workspace()`:

```diff
  ws_id = self.kwargs.get('workspace_id') if hasattr(self, 'kwargs') else None
  if ws_id is not None:
      ws = Workspace.objects.filter(pk=ws_id, is_active=True).first()
-     if ws is not None:
+     if ws is not None and user_workspaces(self.request.user).filter(pk=ws.pk).exists():
          return ws
```

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
