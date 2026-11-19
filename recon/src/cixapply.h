#ifndef CIXAPPLY_H
#define CIXAPPLY_H

/* Apply a CIX manifest from an already-extracted CAB.  RAW targets are copied
 * from their source entries, PA30 deltas are applied with DeltaApply(), and
 * basis chains are resolved by repeatedly visiting unresolved files. */
int CixApplyCab(const char *cabPath, const char *outDir);

#endif /* CIXAPPLY_H */
