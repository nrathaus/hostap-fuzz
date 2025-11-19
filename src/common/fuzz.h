
#ifndef FUZZ_H
#define FUZZ_H

void apply_mutation(struct ieee80211_mgmt *buf, size_t len);

#endif
