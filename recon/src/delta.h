#ifndef DELTA_H
#define DELTA_H

/* Detect a PA19/PA30 delta blob and apply it to source data.
 * Returns 0 on success, -1 otherwise.  On success *out is malloc'd. */
int DeltaApply(const unsigned char *delta, unsigned long deltaLen,
               const unsigned char *source, unsigned long sourceLen,
               unsigned char **out, unsigned long *outLen);
int DeltaIsDelta(const unsigned char *delta, unsigned long deltaLen);

#endif
