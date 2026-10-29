# Model RMSNorm records and numerical composition — Q26

Status: Draft RFC-0004 A3/A8/A9 model evidence using Accepted RFC-0021 §2.3 and
RFC-0022's unchanged RMSNorm schema/bytes. E5-03 remains blocked; original
acceptance and NC-0109 are unchanged.

Question: can every layer/final norm derive its expected record from model
metadata and connect checked input/gain rows to the following row conversion,
with native full-byte and arithmetic agreement? Source associations and static
integer faithfulness are at stake; cost terms are T_misc/c_a/T_witness.

Kill criterion, stated before implementation: drop the adapter if it omits or
deduplicates a required role, adopts actual magnitudes, accepts a substituted
record/source, or disagrees with the independent/native references. No new
norm schema, table, Accepted format, proof consumer or measured constant.
