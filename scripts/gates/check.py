#!/usr/bin/env python3
"""RFC-0020 §5: fail closed until each protocol gate has its real producer.

The hashes identify empty scaffolds only. They are not proof reference digests.
Replace a guard with the actual validator in the task named in its diagnostic.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
# Guard only crates that can introduce the corresponding proof obligations.
SCOPES = {
    'digest': ('prover', 'proof'),
    'negative-controls': ('verifier',),
    'soundness-accounting': ('verifier',),
    'parity': ('gpu', 'kernels'),
}
OWNERS = {
    'digest': 'E8-06', 'negative-controls': 'E0-03',
    'soundness-accounting': 'E2-01 / E8-05', 'parity': 'E10-01',

}
ARTIFACTS = {
    'digest': ('tests/digests',),
    'negative-controls': (),
    'soundness-accounting': ('tests/soundness',),
    'parity': ('tests/parity',),
}


def bootstrap_guard(root, gate):
    """An absent implementation may pass; an unvalidated implementation may not."""
    baseline = json.loads((root / 'scripts/gates/bootstrap-sources.json').read_text())
    for name in SCOPES.get(gate, ()):
        crate = root / f'crates/stele-{name}'
        expected = baseline[f'stele-{name}']
        actual = {str(p.relative_to(crate)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in crate.rglob('*') if p.is_file()}
        if actual != expected:
            raise ValueError(f'{gate}: validator not wired for changed {crate.relative_to(root)}; '
                             f'implement the gate with its producer (task {OWNERS[gate]})')
    for directory in ARTIFACTS[gate]:
        for file in (root / directory).rglob('*'):
            if file.is_file() and file.name not in {'catalog.md', 'README.md', '.gitkeep'}:
                raise ValueError(f'{gate}: validator not wired for {file.relative_to(root)} '
                                 f'(task {OWNERS[gate]})')
    print(f'gate {gate}: remaining scaffold guards verified (task {OWNERS[gate]})')


def field_sources(root):
    """Closed conditional A1/stacked/lookup consumers; no inference/profile authority."""
    crate = root / 'crates/stele-reductions'
    allowed = {'Cargo.toml', 'src/lib.rs', 'src/field_sources.rs', 'src/stacked_sources.rs', 'tests/stacked.rs',
               'src/lookup.rs', 'src/lookup_sizes_tests.rs', 'tests/lookup_codec.rs',
               'src/lookup_producer.rs', 'src/lookup_resources.rs', 'src/lookup_functionals.rs',
               'tests/lookup_producer.rs', 'src/lookup_verifier.rs', 'src/lookup_records.rs',
               'tests/lookup_verifier.rs', 'src/lookup_work.rs'}
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
    dependencies = {f'stele-{n}': {'path': f'../stele-{n}'}
                    for n in ('field', 'hash', 'sumcheck', 'gkr', 'lookup', 'pcs', 'ir', 'cqis', 'poly')}
    library = ('//! Closed original field-source consumer for RFC-0006 A1, governed by RFC-0010 A9 §5.\n'
               '#![forbid(unsafe_code)]\n#![no_std]\n'
               '#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n'
               'extern crate alloc;\nmod field_sources;\npub mod lookup;\n'
               'pub use field_sources::{verify_field_sources, Error, Failure, FieldSourceRecord};\n'
               'mod stacked_sources;\npub use stacked_sources::{\n'
               '    prove_stacked_sources, prove_stacked_sources_measured, verify_stacked_sources,\n'
               '    Error as StackedError, Failure as StackedFailure, StackedProof, StackedSourceRecord,\n};\n')
    code = re.sub(r'//[^\n]*', '', (crate / 'src/field_sources.rs').read_text())
    declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', code)
    stacked = re.sub(r'//[^\n]*', '', (crate / 'src/stacked_sources.rs').read_text())
    stacked_declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', stacked)
    stacked_closed = (stacked_declarations == [
        ('enum', 'Error'), ('struct', 'Failure'), ('', 'cause'), ('', 'usage'),
        ('struct', 'StackedProof'), ('', 'sumcheck'), ('', 'openings'),
        ('struct', 'StackedSourceRecord'), ('fn', 'sc'), ('fn', 'openings'),
        ('fn', 'verify_stacked_sources'), ('fn', 'prove_stacked_sources'), ('fn', 'prove_stacked_sources_measured')]
        and len(stacked_declarations) == len(re.findall(r'\bpub\b', stacked))
        and [re.sub(r'\s+', '', item) for item in re.findall(r'\bimpl\b[^\{]*\{', stacked)]
            == ["impl<K:ChallengeField>StackedSourceRecord<'_,K>{"]
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', stacked))
    lookup = re.sub(r'//[^\n]*', '', (crate / 'src/lookup.rs').read_text())
    lookup_declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', lookup)
    lookup_closed = (lookup_declarations == [
        ('use', 'stele_cqis'), ('enum', 'Error'), ('struct', 'Layout'), ('', 'id'), ('', 'ell'), ('', 'blowup'),
        ('struct', 'Limits'), ('', 'positions'), ('', 'public_bytes'), ('', 'proof_bytes'),
        ('struct', 'Statement'), ('', 'id'), ('', 'm'), ('', 'b'), ('', 'table'), ('', 'selector'),
        ('', 'originals'), ('', 'multiplicities'), ('struct', 'Descriptor'), ('fn', 'new'),
        ('fn', 'statement_size'), ('fn', 'proof_size'), ('fn', 'public_bytes'), ('fn', 'max_local_hashes'),
        ('fn', 'multiplicity_source'), ('fn', 'encode'), ('fn', 'preflight'), ('use', 'producer'), ('use', 'verifier')]
        and len(lookup_declarations) == len(re.findall(r'\bpub\b', lookup))
        and [re.sub(r'\s+', '', item) for item in re.findall(r'\bimpl\b[^\{]*\{', lookup)]
            == ["impl<'input,'cert,K:ChallengeField>Descriptor<'input,'cert,K>{"]
        and 'pubusestele_cqis::tables::{DescriptorasTableDescriptor,Table,TableField};' in re.sub(r'\s+', '', lookup)
        and 'pubuseproducer::{ProducerLimits,ProverFailure,ProverUsage,ProverWork,RegistrationUsage,RepetitionWork,};' in re.sub(r'\s+', '', lookup)
        and 'pubuseverifier::{Failure,LookupParameters,LookupRecord,RegisteredMultiplicities,RegistrationFailure,RepetitionRecord,};' in re.sub(r'\s+', '', lookup)
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', lookup))
    producer_closed = True
    for name, visibility, expected, impls in (
        ('producer', 'pub', [('use','work'), ('struct','ProducerLimits'), ('','public_bytes'), ('','dense_elements'),
            ('struct','RegistrationUsage'), ('','production'), ('','verification'),
            ('struct','ProverUsage'), ('','transcript'), ('','non_transcript'), ('','registrations'),
            ('struct','ProverFailure'), ('','cause'), ('','usage'),
            ('fn','producer_public_bytes'), ('fn','producer_dense_elements'), ('fn','prove'), ('fn','prove_measured')],
         ["impl<K:ChallengeField+CodeField+TableField+Eq>Descriptor<'_,'_,K>wherefor<'a>K::Bytes:TryFrom<&'a[u8]>,{"]),
        ('resources', 'pub(super)', [('fn','elements')], []),
        ('work', ['pub']*20+['pub(super)']*7,
         [('struct','RepetitionWork'), ('','lookup'), ('','table'), ('','selected'),
          ('struct','ProverWork'), ('','proof_bytes'), ('','units_bytes'), ('','index_bytes'),
          ('','group_weights_bytes'), ('','mu_values_bytes'), ('','mu_limbs_bytes'), ('','originals_bytes'),
          ('','selector_bytes'), ('','prepared_bytes'), ('','coefficients_bytes'), ('','temporary_wire_bytes'),
          ('','local_peak_observed_bytes'), ('','peak_observed_bytes'), ('','preparations'), ('','repetitions'),
          ('fn','bytes'), ('fn','vectors'), ('fn','proof'), ('fn','tree'), ('fn','local'), ('fn','child'), ('fn','wire')],
         ['implProverWork{']),
        ('functionals', 'pub(super)', [('struct','Piece'), ('','id'), ('','a'), ('','b'),
             ('fn','value'), ('fn','pieces')], ['impl<K:ChallengeField>Piece<K>{']),
        ('verifier', 'pub', [('use','records'), ('struct','Failure'), ('','cause'), ('','usage'),
             ('struct','RegistrationFailure'), ('','cause'), ('','registrations'),
             ('type','RegisteredMultiplicities'), ('fn','register_multiplicities'), ('fn','verify')],
         ["impl<'input,'original,K:ChallengeField+CodeField+TableField+Eq>Descriptor<'input,'original,K>wherefor<'a>K::Bytes:TryFrom<&'a[u8]>,{"]),
        ('records', ['pub']*11+['pub(super)']*5+['pub']*6+['pub(super)']*2+['pub']*2,
         [('struct','LookupParameters'), ('','id'), ('','degree'), ('','positions'), ('','table_rows'),
          ('','columns'), ('','group_bits'), ('','unit_bits'), ('','repetitions'), ('','identity_numerator'),
          ('struct','RepetitionRecord'), ('','lookup'), ('','table'), ('','selected'), ('','originals'), ('','multiplicities'),
          ('fn','lookup_tree'), ('fn','table_tree'), ('fn','selected_product'), ('fn','originals'), ('fn','multiplicities'),
          ('struct','LookupRecord'), ('','parameters'), ('','repetitions'), ('fn','parameters'), ('fn','repetitions')],
         ["impl<K:ChallengeField>RepetitionRecord<'_,K>{", "impl<K:ChallengeField>LookupRecord<'_,K>{"]),
    ):
        source = re.sub(r'//[^\n]*', '', (crate / f'src/lookup_{name}.rs').read_text())
        # Private helpers may expose only the explicitly reviewed parent interface.
        public = re.findall(r'\bpub\b(?:\s*\([^)]*\))?', source)
        normalized = source.replace('pub(super)', 'pub')
        found = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', normalized)
        expected_visibility = visibility if isinstance(visibility, list) else [visibility] * len(expected)
        producer_closed &= (public == expected_visibility and found == expected
            and [re.sub(r'\s+', '', item) for item in re.findall(r'\bimpl\b[^\{]*\{', source)] == impls
            and (name != 'verifier' or 'pubuserecords::{LookupParameters,LookupRecord,RepetitionRecord};' in re.sub(r'\s+', '', source))
            and (name != 'producer' or 'pubusework::{ProverWork,RepetitionWork};' in re.sub(r'\s+', '', source))
            and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', source))
    oracle = root / 'tests/negative-controls/lookup_corpus.py'
    if (actual != allowed or (crate / 'src/lib.rs').read_text() != library
            or manifest.get('dependencies') != dependencies
            or any(k in manifest for k in ('dev-dependencies', 'build-dependencies', 'target', 'features'))
            or 'build' in manifest.get('package', {})
            or declarations != [('enum', 'Error'), ('struct', 'Failure'), ('', 'cause'), ('', 'usage'),
                                ('struct', 'FieldSourceRecord'), ('fn', 'sc'), ('fn', 'openings'),
                                ('fn', 'verify_field_sources')]
            or len(declarations) != len(re.findall(r'\bpub\b', code))
            or not stacked_closed or not lookup_closed or not producer_closed
            or any(not (oracle.parent/name).is_file() for name in ('lookup_corpus.py', 'lookup_corpus.py.lock',
                'lookup_closed.py', 'examples/support/lookup_verifier.rs'))):
        raise ValueError('reductions API not wired; only reviewed conditional A1/stacked/lookup adapters admitted')
    checks = [
        (['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'pcs_a1::'],
         [f'test pcs_a1::{n} ... ok' for n in (
             'accepts_qm31_closed_originals', 'accepts_om31_closed_originals',
             'rejects_qm31_later_source_and_roster', 'rejects_om31_later_source_and_roster',
             'matches_reference_closed_a1_bytes')]),
        (['cargo', 'test', '-p', 'stele-negative-controls', '--test', 'nc-0609'],
         ['test rejects_unused_original_final ... ok']),
        (['cargo', 'test', '-p', 'stele-reductions', '--doc'],
         ['compile fail ... ok']),
        (['cargo', 'test', '-p', 'stele-reductions', '--test', 'stacked'],
         [f'test {name} ... ok' for name in ('accepts_qm31_certified_stacked_sources',
          'accepts_om31_certified_stacked_sources', 'rejects_qm31_malformed_certified_stacked_sources',
          'rejects_om31_malformed_certified_stacked_sources')]),
        (['cargo', 'test', '-p', 'stele-negative-controls', '--test', 'stacked-certified'],
         ['test rejects_wrong_restored_point_at_actual_opening ... ok',
          'test rejects_substituted_verified_certificate_at_actual_opening ... ok']),
        (['cargo', 'test', '-p', 'stele-reductions', '--lib', 'lookup::'],
         [f'test lookup::sizes_tests::matches_reference_{field}_lookup_sizes ... ok' for field in ('qm31','om31')]
         + [f'test lookup::functionals::tests::matches_reference_{field}_lookup_prefix_functionals ... ok'
            for field in ('qm31','om31')]),
        (['cargo', 'test', '-p', 'stele-reductions', '--test', 'lookup_codec'],
         [f'test {prefix}_{field}_lookup_{suffix} ... ok' for field in ('qm31','om31')
          for prefix,suffix in (('matches_reference','statement'),('rejects','shape_and_limits'))]),
        (['cargo', 'test', '-p', 'stele-reductions', '--test', 'lookup_producer'],
         [f'test {prefix}_{field}_lookup_producer_{suffix} ... ok' for field in ('qm31','om31')
          for prefix,suffix in (('accepts','registrations'),('rejects','before_mutation'),('rejects','after_registration'))]),
        (['cargo', 'test', '-p', 'stele-reductions', '--test', 'lookup_verifier'],
         [f'test {prefix}_{field}_closed_lookup{suffix} ... ok' for field in ('qm31','om31')
          for prefix,suffix in (('accepts',''),('rejects','_tampers'))]),
        (['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'lookup::'],
         [f'test lookup::accepts_{field}_nonzero_lookup_tail ... ok' for field in ('qm31','om31')]),
        (['cargo', 'test', '-p', 'stele-negative-controls']+
         [arg for i in (400,401,402,403,415,416,417,418,419,610,802) for arg in ('--test',f'nc-{i:04}')],
         [f'test rejects_nc_{i:04} ... ok' for i in (400,401,402,403,415,416,417,418,419,610,802)]),
    ]
    for command, expected in checks:
        result = subprocess.run([*command, '--locked', '--offline'], cwd=root, text=True, capture_output=True)
        if result.returncode or any(text not in result.stdout for text in expected):
            raise ValueError(f'closed A1 consumer checks failed: {result.stdout} {result.stderr}')
        if '--doc' in command:
            for file, module, record, count in (('field_sources', 'field_sources', 'FieldSourceRecord', 1),
                                          ('stacked_sources', 'stacked_sources', 'StackedSourceRecord', 2),
                                          ('lookup', 'lookup', 'Statement', 1), ('lookup', 'lookup', 'Descriptor', 1),
                                          ('lookup_records', 'lookup::verifier::records', 'LookupRecord', 3)):
                pattern = (rf'^test crates/stele-reductions/src/{file}\.rs - {module}::{record} '
                           r'\(line \d+\) - compile fail \.\.\. ok$')
                matches = re.findall(pattern, result.stdout, re.MULTILINE)
                if len(set(matches)) != count:
                    raise ValueError(f'closed A1 consumer checks failed: missing {record} boundary')
    result = subprocess.run(['uv', 'run', '--python', '3.12', '--locked', '--script',
                             'tests/negative-controls/lookup_corpus.py'],
                            cwd=root, text=True, capture_output=True)
    receipt = ('lookup producer corpus: 8 complete cases; QM31/OM31; bytes, registration, usage, public payloads and continuation; '
               'SHA256 cb8e5b658bbd7f5ed6c917f36605daf33331a7fa46e12eb31d7584c0d76887c9; no lookup verification credit\n'
               'lookup closed corpus: 40 complete cases; QM31/OM31; 8 accepts and 32 rejects; actual records, imports, failure usage and continuation; '
               'SHA256 ce40cdb3b09cf153b6f81a4962abe2e8959c38e05f6d71b149a2f486a1574a41')
    if result.returncode or result.stdout.strip() != receipt:
        raise ValueError(f'lookup producer corpus checks failed: {result.stdout} {result.stderr}')
    print('gate closed A1: all original claims, full Python bytes, NC-0609 and lifetime boundary; no profile credit')
    print('gate stacked certified: actual A1/A7/A9 producer and consumers, NC-0211/0213, budgets and certificate lifetime; no profile credit')
    print('gate lookup codec: exact statement/wire, cumulative budgets and borrowed handles; no lookup verification or NC credit')
    print('gate lookup producer: actual A3/A9 production, independent bytes and observed usage; no lookup verification or NC credit')
    print('gate lookup closed: actual A3/Table/A9 consumers, opaque records, native controls and independent failure/usage parity; no profile credit')


def field_source_codec(root):
    """A9 consumers and A10 retained rows; complete profiles remain guarded."""
    crate = root / 'crates/stele-pcs'
    allowed = {'Cargo.toml', 'src/lib.rs', 'src/source.rs', 'src/preparation.rs',
               'src/producer.rs', 'src/producer_tests.rs', 'src/certificate.rs', 'src/certificate_tests.rs',
               'tests/fixtures/certificate-continuation.txt',
               'tests/field_source.rs', 'tests/preparation.rs',
               'src/opening.rs', 'tests/opening.rs', 'tests/fixtures/opening-continuation.txt',
               'tests/fixtures/field-wire.jsonl', 'examples/field_policy.rs'}
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    library = ('//! Conditional Circle field sources, certificates and functional openings, RFC-0010 A9/A10.\n'
               '//!\n//! Verification retains conditional obligations; A1 closure and profiles remain separate.\n'
               '#![forbid(unsafe_code)]\n#![no_std]\n'
               '#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n'
               'extern crate alloc;\nmod certificate;\nmod opening;\nmod preparation;\nmod producer;\nmod source;\n'
               'pub use certificate::{verify_certificate, CertificateRecord, Failure, Usage, VerifiedCertificate};\n'
               'pub use opening::{\n'
               '    verify_opening, verify_point, Functional, OpeningRecord, RetainedRow, RetainedRowWork,\n};\n'
               'pub use preparation::{PreparationWork, PreparedColumn, PreparedSource};\n'
               'pub use producer::CertificateFailure;\n'
               'pub use source::{Error, Parameters, ProofKind, Response, Source, Wire};\n'
               'pub use stele_code::CodeField;\n')
    manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
    dependencies = {f'stele-{name}': {'path': f'../stele-{name}'} for name in ('code', 'field', 'hash', 'poly')}
    source = (crate / 'src/source.rs').read_text()
    # Closed reviewed API inventory, not a semantic Rust sandbox or source-hash rebaseline.
    code = re.sub(r'//[^\n]*', '', source)
    declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', code)
    surface = [(kind or 'field', name) for kind, name in declarations]
    expected_surface = [('enum', 'Error'), ('enum', 'ProofKind'), ('struct', 'Parameters'),
        ('field', 'length'), ('field', 'distance'), ('field', 'radius'),
        ('field', 'certificate_queries'), ('field', 'opening_queries'), ('struct', 'Source'),
        ('fn', 'new'), ('fn', 'bytes'), ('fn', 'rows'), ('fn', 'columns'), ('fn', 'code'), ('fn', 'root'), ('fn', 'path_height'),
        ('fn', 'descriptor'), ('fn', 'parameters'), ('fn', 'queries'), ('fn', 'proof_size'), ('fn', 'opening_frame_size'),
        ('fn', 'parse'), ('struct', 'Response'), ('field', 'payload'), ('field', 'siblings'),
        ('struct', 'Wire'), ('fn', 'row_bytes'), ('fn', 'response_bytes'), ('fn', 'responses')]
    compact = lambda text: re.sub(r'\s+', '', text)
    impls = [compact(text) for text in re.findall(r'\bimpl\b[^\{]*\{', code)]
    derives = [compact(text) for text in re.findall(r'#\[[^\]]*\]', code)]
    imports = [compact(text) for text in re.findall(r'\buse\s+[^;]+;', code)]
    enums = [(name, compact(body)) for name, body in re.findall(r'pub enum (\w+)\s*\{([^}]*)\}', code)]
    closed_surface = (surface == expected_surface
        and len(declarations) == len(re.findall(r'\bpub\b', code))
        and impls == ['impl<K:ChallengeField>Source<K>{', "impl<'a>Wire<'a>{",
                      "implExactSizeIterator<Item=Response<'a>>+'_{"]
        and derives == ['#[derive(Clone,Copy,Debug,Eq,PartialEq)]']*3
            + ['#[derive(Clone,Copy,Debug)]']*3
        and imports == ['usecore::marker::PhantomData;', 'usestele_code::Circle;',
            'usestele_field::{Serialize,M31};', 'usestele_hash::{merkle,ChallengeField};']
        and enums == [('Error', 'UnsupportedSource,ProofShape,NoncanonicalField,MessageShape,'
                       'Encoder(stele_code::Error),Merkle(merkle::Error),Transcript(stele_hash::Error),ColumnMismatch,'
                       'FunctionalShape,ValueMismatch,CertificateContext,RowContext,Capacity,'),
                      ('ProofKind', 'Certificate,Opening,')]
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', code))
    prepared = re.sub(r'//[^\n]*', '', (crate / 'src/preparation.rs').read_text())
    prepared_declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', prepared)
    prepared_surface = [(kind or 'field', name) for kind, name in prepared_declarations]
    prepared_closed = (prepared_surface == [
        ('struct', 'PreparationWork'), ('field', 'borrowed_message_bytes'),
        ('field', 'encoded_columns_bytes'), ('field', 'encoder_peak_bytes'),
        ('field', 'leaf_references_bytes'), ('field', 'merkle_nodes_bytes'), ('field', 'peak_owned_bytes'),
        ('struct', 'PreparedColumn'), ('field', 'payload'), ('field', 'siblings'),
        ('struct', 'PreparedSource'), ('fn', 'new'), ('fn', 'source'), ('fn', 'message'),
        ('fn', 'response'), ('fn', 'work')]
        and len(prepared_declarations) == len(re.findall(r'\bpub\b', prepared))
        and [compact(text) for text in re.findall(r'\bimpl\b[^\{]*\{', prepared)]
            == ["impl<'a,K:ChallengeField>PreparedSource<'a,K>{"]
        and [compact(text) for text in re.findall(r'\buse\s+[^;]+;', prepared)] == [
            'usecrate::{Error,Source};', 'usealloc::vec::Vec;', 'usecore::mem::size_of;',
            'usestele_code::Encoder;', 'usestele_field::{Serialize,M31};',
            'usestele_hash::{merkle,ChallengeField,HashUsage};', 'usesuper::*;']
        and [compact(text) for text in re.findall(r'#\[[^\]]*\]', prepared)]
            == ['#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)]', '#[cfg(test)]', '#[test]']
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', prepared))
    producer = re.sub(r'//[^\n]*', '', (crate / 'src/producer.rs').read_text())
    producer_declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', producer)
    producer_closed = (producer_declarations == [('struct', 'CertificateFailure'),
        ('', 'cause'), ('', 'usage'), ('fn', 'certificate')]
        and len(producer_declarations) == len(re.findall(r'\bpub\b', producer))
        and [compact(text) for text in re.findall(r'\bimpl\b[^\{]*\{', producer)]
            == ["impl<K:ChallengeField>PreparedSource<'_,K>{"]
        and [compact(text) for text in re.findall(r'\buse\s+[^;]+;', producer)] == [
            'usecrate::{Error,PreparedSource,ProofKind,Source};', 'usealloc::vec::Vec;',
            'usestele_hash::{AbsorbLabel,ChallengeField,ChallengeLabel,HashUsage,Transcript};']
        and [compact(text) for text in re.findall(r'#\[[^\]]*\]', producer)] == [
            '#[derive(Clone,Copy,Debug,Eq,PartialEq)]', '#[cfg(test)]', '#[path="producer_tests.rs"]']
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', producer))
    certificate = re.sub(r'//[^\n]*', '', (crate / 'src/certificate.rs').read_text())
    certificate_declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', certificate)
    certificate_closed = (certificate_declarations == [
        ('struct', 'Usage'), ('', 'transcript'), ('', 'non_transcript'),
        ('struct', 'Failure'), ('', 'cause'), ('', 'usage'), ('struct', 'CertificateRecord'),
        ('fn', 'source'), ('fn', 'id'), ('fn', 'parameters'), ('fn', 'ell'), ('fn', 'degree'),
        ('fn', 'kind'), ('struct', 'VerifiedCertificate'), ('fn', 'record'), ('fn', 'verify_certificate')]
        and len(certificate_declarations) == len(re.findall(r'\bpub\b', certificate))
        and [compact(text) for text in re.findall(r'\bimpl\b[^\{]*\{', certificate)] == [
            'impl<K:ChallengeField>CertificateRecord<K>{', 'impl<K:ChallengeField>VerifiedCertificate<K>{']
        and [compact(text) for text in re.findall(r'\buse\s+[^;]+;', certificate)] == [
            'usecrate::{Error,Parameters,ProofKind,Source,Wire};', 'usealloc::vec::Vec;',
            'usestele_code::{CodeField,Encoder};', 'usestele_field::{Serialize,M31};',
            'usestele_hash::{certificate_id,merkle,AbsorbLabel,ChallengeField,ChallengeLabel,HashUsage,Transcript,};']
        and [compact(text) for text in re.findall(r'#\[[^\]]*\]', certificate)] == [
            '#[derive(Clone,Copy,Debug,Default,Eq,PartialEq)]', '#[derive(Clone,Copy,Debug,Eq,PartialEq)]',
            '#[cfg(test)]', '#[path="certificate_tests.rs"]']
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', certificate))
    opening = re.sub(r'//[^\n]*', '', (crate / 'src/opening.rs').read_text())
    opening_declarations = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', opening)
    opening_closed = (opening_declarations == [
        ('struct', 'Functional'), ('', 'id'), ('', 'a'), ('', 'b'), ('', 'value'), ('fn', 'verify_point'),
        ('struct', 'OpeningRecord'), ('fn', 'certificate'), ('fn', 'id'), ('fn', 'queries'),
        ('fn', 'kind'), ('struct', 'RetainedRowWork'), ('', 'source_visits'),
        ('', 'source_elements'), ('', 'retained_bytes'), ('struct', 'RetainedRow'),
        ('fn', 'new'), ('fn', 'values'), ('fn', 'work'), ('fn', 'opening'),
        ('fn', 'opening_point'), ('fn', 'opening'), ('fn', 'verify_opening')]
        and len(opening_declarations) == len(re.findall(r'\bpub\b', opening))
        and [compact(text) for text in re.findall(r'\bimpl\b[^\{]*\{', opening)] == [
            "impl<K:ChallengeField>Functional<'_,K>{", "impl<K:ChallengeField>OpeningRecord<'_,K>{",
            "impl<'prepared,'message,K:ChallengeField>RetainedRow<'prepared,'message,K>{",
            "impl<K:ChallengeField>PreparedSource<'_,K>{"]
        and [compact(text) for text in re.findall(r'\buse\s+[^;]+;', opening)] == [
            'usecrate::{CertificateRecord,Error,Failure,PreparedSource,ProofKind,Source,Usage,VerifiedCertificate,};',
            'usealloc::vec::Vec;', 'usestele_code::{CodeField,Encoder};', 'usestele_field::{Serialize,M31};',
            'usestele_hash::{merkle,AbsorbLabel,ChallengeField,HashUsage,Transcript};']
        and [compact(text) for text in re.findall(r'#\[[^\]]*\]', opening)] == [
            '#[derive(Clone,Copy)]', '#[derive(Clone,Copy,Debug,Eq,PartialEq)]', '#[cfg(test)]', '#[test]']
        and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', opening))
    if (actual != allowed or (crate / 'src/lib.rs').read_text() != library
            or not closed_surface or not prepared_closed or not producer_closed or not certificate_closed
            or not opening_closed
            or manifest.get('dependencies') != dependencies
            or manifest.get('dev-dependencies') != {'serde_json': '=1.0.154'}
            or any(key in manifest for key in ('build-dependencies', 'target', 'features'))
            or 'build' in manifest.get('package', {})):
        raise ValueError('PCS API not wired; only reviewed A9 source/certificate/opening and A10 retained-row APIs admitted')
    checks = [
        (['cargo', 'test', '-p', 'stele-pcs', '--locked', '--offline'],
         ['test matches_reference_qm31_source_and_wire ... ok',
          'test matches_reference_om31_source_and_wire ... ok',
          'test rejects_unsupported_sources_without_allocation ... ok',
          'test accepts_maximum_source_shape_without_domain_allocation ... ok',
          'test preparation::tests::rejects_preparation_allocation_sizes ... ok',
          'test opening::rejects_retained_row_allocation_sizes ... ok',
          'test matches_reference_qm31_prepared_columns ... ok',
          'test matches_reference_om31_prepared_columns ... ok',
          'test rejects_preparation_shape_and_hash_overflow ... ok',
          'test producer::tests::matches_reference_qm31_certificate_production ... ok',
          'test producer::tests::matches_reference_om31_certificate_production ... ok',
          'test certificate::tests::matches_reference_qm31_certificates ... ok',
          'test certificate::tests::matches_reference_om31_certificates ... ok',
          'test matches_reference_qm31_openings ... ok',
          'test matches_reference_om31_openings ... ok']),
        (['python3', 'research/merkle-oracle/check_native_policy.py', '--native'],
         ['59 native query pairs match exact independently checked minima']),
        (['uv', 'run', '--locked', '--script', 'research/merkle-oracle/check_field_wire.py'],
         ['4e5327828a8fe47f4b44537278f550e6231da0415022474110b56d6113a8b7ed']),
    ]
    for command, expected in checks:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or any(text not in result.stdout for text in expected):
            raise ValueError(f'field source codec checks failed: {result.stdout} {result.stderr}')
        if command[0] == 'cargo':
            expected_boundaries = {
                ('certificate.rs', 'certificate::VerifiedCertificate'): 1,
                ('opening.rs', 'opening::OpeningRecord'): 2,
                ('opening.rs', 'opening::RetainedRow'): 4,
                ('preparation.rs', 'preparation::PreparedSource'): 1,
                ('source.rs', 'source::Source'): 1,
            }
            boundaries = re.findall(
                r'^test crates/stele-pcs/src/(\S+) - (\S+) \(line (\d+)\) - compile fail \.\.\. ok$',
                result.stdout, re.MULTILINE)
            actual_boundaries = {}
            for file, target, line in boundaries:
                actual_boundaries.setdefault((file, target), set()).add(line)
            if (len(boundaries) != sum(expected_boundaries.values())
                    or {key: len(lines) for key, lines in actual_boundaries.items()} != expected_boundaries):
                raise ValueError('field source codec checks failed: missing compile-fail boundary')
    print('gate PCS: native certificates/openings/retained rows/continuations and all59 policies; A1 checked separately; no matmul/profile credit')


def fraction_reductions(root):
    """Actual A3 tree/selected-product producers and consumers; full lookup stays guarded."""
    crate = root / 'crates/stele-lookup'
    allowed = {'Cargo.toml', 'src/lib.rs', 'src/fraction.rs', 'tests/codec.rs',
               'tests/fixtures/fraction-codec.jsonl', 'src/tree.rs', 'tests/tree.rs',
               'src/leaf_codec.rs', 'tests/leaf_codec.rs', 'tests/fixtures/leaf-codec.jsonl',
               'src/selected.rs', 'tests/selected.rs', 'src/work.rs', 'tests/work.rs',
               'examples/fraction_corpus.rs', 'examples/fraction_bench.rs'}
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    library = ('//! Conditional fraction primitives governed by RFC-0008 A3.\n//!\n'
               '//! Tree and selected-product arithmetic return conditional claims; full lookup is absent.\n'
               '//! ```compile_fail\n//! use stele_lookup::fraction::verify_lookup;\n//! ```\n'
               '#![forbid(unsafe_code)]\n#![no_std]\n'
               '#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n'
               'extern crate alloc;\npub mod fraction;\n')
    manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
    dependencies = {f'stele-{name}': {'path': f'../stele-{name}'} for name in ('gkr','hash','sumcheck','poly')}
    if (actual != allowed or (crate / 'src/lib.rs').read_text() != library
            or manifest.get('dependencies') != dependencies
            or manifest.get('dev-dependencies') != {'stele-field': {'path': '../stele-field'}, 'serde_json': '1.0'}
            or any(key in manifest for key in ('build-dependencies','target','features'))
            or 'build' in manifest.get('package', {})):
        raise ValueError('fraction engine/lookup validator not wired; only A3 conditional reductions/codecs admitted (E3-07a)')
    result = subprocess.run(['cargo','test','-p','stele-lookup','--locked','--offline'],
                            cwd=root,text=True,capture_output=True)
    names = ('matches_reference_qm31_fraction_codec','matches_reference_om31_fraction_codec',
             'rejects_fraction_codec_boundaries','accepts_maximum_verifier_shape_without_domain_allocation',
             'accepts_qm31_fraction_tree_original_consumers','accepts_om31_fraction_tree_original_consumers',
             'rejects_fraction_tree_source_shape_and_poles', 'rejects_qm31_leaf_codec_boundaries',
             'rejects_om31_leaf_codec_boundaries', 'matches_reference_qm31_selected_product_codec',
             'matches_reference_om31_selected_product_codec',
             'accepts_qm31_selected_product_original_consumers','accepts_om31_selected_product_original_consumers',
             'rejects_selected_product_context_and_source_shapes',
             'matches_reference_qm31_fraction_work', 'matches_reference_om31_fraction_work',
             'rejects_qm31_measured_fraction_failures', 'rejects_om31_measured_fraction_failures')
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in names):
        raise ValueError(f'fraction codec checks failed: {result.stdout} {result.stderr}')
    result = subprocess.run(['uv','run','--locked','--script',
                             'research/logup-characteristic/check_fraction.py','--codec'],
                            cwd=root,text=True,capture_output=True)
    if result.returncode or '12 both-field native codec fixtures match' not in result.stdout:
        raise ValueError(f'fraction codec reference drift: {result.stdout} {result.stderr}')
    result = subprocess.run(['uv','run','--locked','--script',
                             'research/logup-characteristic/check_fraction.py','--leaf-codec'],
                            cwd=root,text=True,capture_output=True)
    if result.returncode or '12 both-field selected-product codec fixtures match' not in result.stdout:
        raise ValueError(f'selected-product codec reference drift: {result.stdout} {result.stderr}')
    result = subprocess.run(['cargo','test','-p','stele-negative-controls','--lib',
                             'fraction_transcript::','--locked','--offline'],
                            cwd=root,text=True,capture_output=True)
    names = ('rejects_fraction_challenge_order_tampers','rejects_fraction_missing_final_continuations')
    if result.returncode or any(f'fraction_transcript::{name} ... ok' not in result.stdout for name in names):
        raise ValueError(f'fraction transcript controls failed: {result.stdout} {result.stderr}')
    fraction_corpus(root)
    result = subprocess.run(['cargo','test','-p','stele-lookup','--example','fraction_bench','--locked','--offline'],
                            cwd=root,text=True,capture_output=True)
    names = ('accepts_fraction_benchmark_original_consumers','rejects_fraction_benchmark_shapes')
    if result.returncode or any(f'tests::{name} ... ok' not in result.stdout for name in names):
        raise ValueError(f'fraction benchmark pipeline failed: {result.stdout} {result.stderr}')
    print('gate fraction reductions: tree/selected-product proofs, original consumers, scoped SC/RLC and continuation match Python; no full lookup/profile credit')


def fraction_corpus(root):
    """Regenerate declared decisions; compare complete independent native/reference output."""
    script = 'research/logup-characteristic/corpus.py'
    path = 'research/logup-characteristic/corpus.jsonl'
    result = subprocess.run(['uv','run','--locked','--script',script,'--check'],
                            cwd=root,text=True,capture_output=True)
    if result.returncode or '162 fraction corpus cases regenerated' not in result.stdout:
        raise ValueError(f'fraction corpus regeneration mismatch: {result.stdout} {result.stderr}')
    outputs = []
    for command in [
        ['cargo','run','-q','-p','stele-lookup','--example','fraction_corpus','--locked','--offline','--',path],
        ['uv','run','--locked','--script',script,path],
    ]:
        result = subprocess.run(command,cwd=root,text=True,capture_output=True)
        if result.returncode:
            raise ValueError(f'fraction corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if len(cases) != 162 or len(outputs[0]) != len(cases) or outputs[0] != outputs[1]:
        raise ValueError('fraction corpus decisions/claims/accounting/continuation mismatch')
    for c, result in zip(cases,outputs[0]):
        if result['name'] != c['name'] or result.get('error','accept') != c['expected']:
            raise ValueError('fraction corpus expected rejection mismatch')
        if c['expected'] != 'accept':
            if set(result) != {'name','error'}:
                raise ValueError('fraction corpus rejected attempt exported partial result')
            continue
        s, d = c['descriptor'], c['degree']
        m = s['m']
        record = lambda i,k: dict(id=i,m=k,degree=3,field_degree=d,numerator=3*k)
        expected = dict(tree_id=s['id'],field_degree=d,gamma=m,fold=m,layers=[record(k,k) for k in range(m)])
        if (result['tree']['accounting'] != expected
                or result['tree']['numerator'] != 3*m*(m-1)//2+2*m
                or [i for i,_ in result['tree']['claims']] != s['leaves']):
            raise ValueError('fraction corpus tree accounting/claim scope mismatch')
        if 'leaf' in c and (result['leaf']['tree_id'] != s['id'] or result['leaf']['sc'] != record(s['id'],m)
                           or [i for i,_ in result['leaf']['claims']] != c['leaf']['sources']):
            raise ValueError('fraction corpus selected-product accounting/claim scope mismatch')
    print('gate fraction corpus: 162 both-field decisions, original claims, scoped records and continuation agree')


def public_coefficients(root):
    """A7 arithmetic plus A4's actual closed public stage and independent bytes."""
    crate = root / 'crates/stele-gkr'
    allowed = {'Cargo.toml', 'src/lib.rs', 'src/public_mle.rs', 'tests/public_mle.rs',
               'src/stacked/mod.rs', 'src/stacked/statement.rs', 'src/stacked/strategy.rs', 'tests/stacked.rs'}
    actual = {str(p.relative_to(crate)) for p in crate.rglob('*') if p.is_file()}
    library = ('//! Conditional stacked field runtime governed by RFC-0006 A4/A7.\n'
               '#![forbid(unsafe_code)]\n#![no_std]\n'
               '#![cfg_attr(not(test), deny(clippy::float_arithmetic))]\n\n'
               'extern crate alloc;\npub mod public_mle;\npub mod stacked;\n')
    manifest = tomllib.loads((crate / 'Cargo.toml').read_text())
    surfaces = {
        'public_mle.rs': ('enum:Error struct:Axis :bits :real enum:Kind struct:Coefficient fn:new fn:evaluate',
                          ["impl<'a,K:Field>Coefficient<'a,K>{"]),
        'stacked/mod.rs': ('use:statement use:strategy enum:Error struct:Failure :cause :usage struct:Record fn:point fn:claims fn:sc fn:prove_public fn:prove_public_measured fn:verify_public fn:verify_reduction',
                           ['impl<K>Record<K>{', "impl<K:ChallengeField+Eq>Prepared<'_,K>{"]),
        'stacked/statement.rs': ('enum:Order struct:Claim :id :axes :point :value struct:Statement :id :axes :order :output :coefficient_id :inputs :terms :selectors :kind :source_id struct:Limits :descriptor_bytes :proof_bytes :prepared_entries :partial_entries :axis_entries struct:Prepared fn:new fn:for_certified_sources fn:bytes fn:instance fn:source_bytes',
                                 ["impl<'a,K:ChallengeField+Eq>Prepared<'a,K>{"]),
        'stacked/strategy.rs': ('struct:Work :dense_entries :partial_entries :round_entries :round_scratch_entries :rounds struct:Dense fn:strategy fn:strategy_m31 fn:work fn:capacity_entries fn:prove fn:into_point fn:partials',
                                ["impl<'a,K:ChallengeField+Eq>Prepared<'a,K>{", "impl<K:ChallengeField+Eq>Dense<'_,'_,K>{", "impl<K:ChallengeField+Eq>Summand<K>for&mutDense<'_,'_,K>{"]),
    }
    closed = True
    for name, (declarations, implementations) in surfaces.items():
        code = re.sub(r'//[^\n]*|pub\(super\)', '', (crate / 'src' / name).read_text())
        found = re.findall(r'\bpub\s+(?:(fn|struct|enum|type|trait|mod|use|const|static)\s+)?(\w+)', code)
        closed &= ([':'.join(item) for item in found] == declarations.split()
                   and len(found) == len(re.findall(r'\bpub\b', code))
                   and [re.sub(r'\s+', '', item) for item in re.findall(r'\bimpl\b[^\{]*\{', code)] == implementations
                   and not re.search(r'\b(?:include|include_str|include_bytes|macro_rules)\s*!', code))
    if (actual != allowed or (crate / 'src/lib.rs').read_text() != library
            or not closed
            or manifest.get('dependencies') != {f'stele-{n}': {'path': f'../stele-{n}'} for n in ('field','poly','hash','sumcheck')}
            or any(key in manifest for key in ('build-dependencies', 'dev-dependencies', 'target', 'features'))
            or 'build' in manifest.get('package', {})):
        raise ValueError('GKR stage/source validator not wired; only reviewed A7/A4 public APIs admitted (E3-06)')
    oracle = root / 'research/stacked-gkr/check_native_wire.py'
    if (not oracle.is_file() or not Path(str(oracle)+'.lock').is_file()
            or not (root/'tests/negative-controls/fixtures/stacked-public.sha256').is_file()
            or not (root/'tests/negative-controls/fixtures/stacked-certified.sha256').is_file()):
        raise ValueError('stacked wire checks failed: missing locked checker')
    tests = ('matches_reference_qm31_all_kinds', 'matches_reference_om31_all_kinds',
             'rejects_invalid_descriptors_and_resource_limits',
             'accepts_large_masks_and_scalar_axes_without_domain_allocation')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-gkr', '--test', 'public_mle',
                             '--locked', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in tests):
        raise ValueError(f'public coefficient arithmetic checks failed: {result.stdout} {result.stderr}')
    checks = [
        (['cargo','test','-p','stele-gkr','--test','stacked','--locked','--offline'],
         [f'test {n} ... ok' for n in ('matches_reference_qm31_stacked_rounds_and_consumers',
          'matches_reference_om31_stacked_rounds_and_consumers', 'rejects_preflight_without_transcript_mutation',
          'rejects_unaddressable_storage_before_any_transcript_work', 'accepts_empty_constant_and_zero_coefficient_relations',
          'rejects_malformed_statements_sources_and_proofs')]),
        (['cargo','test','-p','stele-negative-controls','--test','stacked-public','--locked','--offline'],
         [f'test {n} ... ok' for n in ('rejects_wrong_layer_coefficient', 'rejects_changed_onehot_and_exact_table_source',
          'rejects_unused_original_at_draw_order_point', 'rejects_missing_stack_or_sources_before_successor')]),
        (['cargo','test','-p','stele-gkr','--doc','--locked','--offline'], ['compile fail ... ok']),
        (['uv','run','--locked','--script','research/stacked-gkr/check_native_wire.py'],
         ['stacked native wire: 116 both-field decisions; complete frames/proofs/restored claims/SC/continuation agree; '
          +(root/'tests/negative-controls/fixtures/stacked-public.sha256').read_text().strip(),
          'stacked certified wire: 48 both-field decisions; actual certificates/producer/openings/records/usage/continuation agree; '
          +(root/'tests/negative-controls/fixtures/stacked-certified.sha256').read_text().strip()]),
    ]
    for command, required in checks:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or any(receipt not in result.stdout for receipt in required):
            raise ValueError(f'stacked public consumer checks failed: {result.stdout} {result.stderr}')
        if '--doc' in command and not re.search(
                r'^test crates/stele-gkr/src/stacked/mod\.rs - stacked::Record \(line \d+\) - compile fail \.\.\. ok$',
                result.stdout, re.MULTILINE):
            raise ValueError('stacked public consumer checks failed: missing opaque Record boundary')
    print('gate stacked public: A7 10000 points/kind/field; actual A4 consumers, controls and public/certified independent bytes')


def transcript_registry(root):
    """Compare the real validated registry producer with the RFC/accounting inventory."""
    command = ['cargo', 'run', '-q', '-p', 'stele-hash', '--example', 'registry', '--locked', '--offline']
    result = subprocess.run(command, cwd=root, text=True, capture_output=True)
    if result.returncode:
        raise ValueError(f'transcript registry producer failed: {result.stderr}')
    actual = [line.split('\t') for line in result.stdout.splitlines()]
    expected = json.loads((root / 'docs/security/transcript-labels.json').read_text())
    if actual != expected:
        raise ValueError('transcript registry mapping mismatch against soundness inventory')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-hash', '--lib', '--all-features', '--locked', '--offline'],
                            cwd=root, text=True, capture_output=True)
    required = ('tests::accepts_the_fixed_registry', 'tests::matches_reference_lookup_label_classes',
                'transcript_tests::matches_reference_transcript_vectors',
                'transcript_tests::rejects_empty_public_input',
                'usage_tests::rejects_unrepresentable_frame_lengths',
                'usage_tests::matches_reference_transcript_usage',
                'usage_tests::rejects_usage_overflow_before_unrecorded_work',
                'usage_tests::rejects_sampling_exhaustion_with_usage',
                'usage_tests::rejects_merkle_overflow_with_usage',
                'pcs::tests::rejects_column_thresholds_exhaustion_and_invalid_domains',
                'pcs::tests::matches_reference_full_field_column_ratchets',
                'pcs::tests::rejects_certificate_id_hash_overflow')
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in required):
        raise ValueError(f'transcript primitive tests failed: {result.stdout}\n{result.stderr}')
    print(f'gate transcript: validated {len(actual)} registry entries; no profile budget certified')


def native_encoder(root):
    """Actual A4 codeword digests and full-byte differential corpus, not PCS proofs."""
    generated = subprocess.run(
        ['uv', 'run', '--locked', '--script', 'research/code-provenance/check_native.py', '--vectors'],
        cwd=root, capture_output=True)
    expected = (root / 'crates/stele-code/tests/encoder-vectors.txt').read_bytes()
    if generated.returncode or generated.stdout != expected:
        raise ValueError(f'native encoder reference digests drift: {generated.stderr.decode()}')
    commands = [
        (['cargo', 'test', '-p', 'stele-code', '--locked', '--offline'],
         ['test matches_reference_materialized_codeword_digests ... ok',
          'test matches_reference_complete_work_and_capacity_all_fields ... ok',
          'test encoder::tests::rejects_outer_inner_and_late_sampling_exhaustion ... ok']),
        (['uv', 'run', '--locked', '--script', 'research/code-provenance/check_native.py'],
         [f'native d={d}: 1006 full words and ordered queries; {{3: 900, 4: 90, 5: 10}} seeds'
          for d in (1, 4, 8)] + ['native corpus: malformed adapter inputs reject; no PCS/profile or NC credit']),
    ]
    for command, receipts in commands:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or any(receipt not in result.stdout for receipt in receipts):
            raise ValueError(f'native encoder gate failed: {result.stdout} {result.stderr}')
    print('gate digest: native encoder digests, sealed API and full-byte corpus checked; no PCS proof claim')


def sumcheck_corpus(root, path='research/sumcheck/corpus.jsonl', features=()):
    """Compare real Rust/Python decisions, all claims and every SC record."""
    commands = [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'corpus', '--locked', '--offline']
        + (['--features', ','.join(features)] if features else []) + ['--', path],
        ['uv', 'run', '--locked', '--script', 'research/sumcheck/check_sumcheck.py', '--verify-corpus', path],
    ]
    outputs = []
    for command in commands:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'sumcheck corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if not cases or outputs[0] != outputs[1] or len(outputs[0]) != len(cases):
        raise ValueError('sumcheck corpus decisions/accounting mismatch')
    for case, result in zip(cases, outputs[0]):
        if result['name'] != case['name'] or result.get('error', 'accept') != case['expected']:
            raise ValueError('sumcheck corpus expected rejection mismatch')
        if case['expected'] == 'accept':
            if len(result['receipts']) != len(case['instances']):
                raise ValueError('sumcheck instance enumeration mismatch')
            for record, receipt in zip(case['instances'], result['receipts']):
                i = record['instance']
                degree = max((len(t['factors']) for t in i['terms']), default=0)
                expected = dict(id=i['id'], m=i['m'], degree=degree, field_degree=case['field_degree'], numerator=i['m']*degree)
                if (receipt['sc'] != expected or len(receipt['point']) != i['m'] or
                    [claim[0] for claim in receipt['claims']] != i['ids']):
                    raise ValueError('sumcheck SC record/challenge count mismatch')
    print(f'gate sumcheck: {len(cases)} actual corpus decisions and SC records; no profile budget certified')


def batch_instances(root):
    """Real instance-batch bytes/records and both-mode production controls."""
    commands = [
        ('matches_reference_batch_bytes_and_accounting', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'batch', '--locked', '--offline']),
        ('batching::rejects_batch_binding_tampers', ['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'batching::', '--locked', '--offline']),
        ('', ['uv', 'run', '--locked', '--script', 'research/batching/check_batching.py', '--instance-vectors']),
    ]
    for test, command in commands:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'batch instance checks failed: {result.stdout} {result.stderr}')
    expected = (root / 'crates/stele-sumcheck/tests/fixtures/batch-instances.jsonl').read_text()
    if result.stdout != expected:
        raise ValueError('batch instance byte/accounting oracle mismatch')
    print('gate batching: instance bytes/SC/RLC and both-mode controls checked; E3-02 remains incomplete')


def batch_claims(root):
    """Check the separate mode-1 prover/verifier and sparse/direct coefficient agreement."""
    tests = ['matches_reference_claim_bytes_and_accounting',
             'matches_reference_coefficients_at_ten_thousand_points_per_field']
    result = subprocess.run(['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'claim_batch', '--locked', '--offline'],
                            cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in tests):
        raise ValueError(f'claim batch checks failed: {result.stdout} {result.stderr}')
    result = subprocess.run(['uv', 'run', '--locked', '--script', 'research/batching/check_batching.py', '--claim-vectors'],
                            cwd=root, text=True, capture_output=True)
    expected = (root / 'crates/stele-sumcheck/tests/fixtures/batch-claims.jsonl').read_text()
    if result.returncode or result.stdout != expected:
        raise ValueError(f'claim batch byte/accounting oracle mismatch: {result.stderr}')
    print('gate claim batching: bytes/SC/RLC and 10000 coefficient points per field checked; no profile certified')



def batch_corpus(root):
    """Compare actual closed-statement decisions, every obligation, and both loss records."""
    path = 'research/batching/corpus.jsonl'
    outputs = []
    for command in [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'batch_corpus', '--locked', '--offline', '--', path],
        ['uv', 'run', '--locked', '--script', 'research/batching/check_batching.py', '--verify-corpus', path],
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'batch corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if not cases or outputs[0] != outputs[1] or len(outputs[0]) != len(cases):
        raise ValueError('batch corpus decisions/obligations/accounting mismatch')
    for case, result in zip(cases, outputs[0]):
        if result['name'] != case['name'] or result.get('error', 'accept') != case['expected']:
            raise ValueError('batch corpus expected rejection mismatch')
        if case['expected'] == 'accept':
            b, d = case['batch'], case['degree']
            if b['mode']:
                m, degree, count, claims = b['m'], 2, len(b['claims']), 1
            else:
                members = b['instances']; m = max(i['m'] for i in members)
                degree = max([int(any(i['m'] != m for i in members))] +
                             [len(factors) for i in members for _, factors in i['terms']])
                count, claims = len(members), sum(len(i['ids']) for i in members)
            if (result['sc'] != dict(id=b['id'], m=m, degree=degree, field_degree=d, numerator=m*degree) or
                result['rlc'] != dict(id=b['id'], t=count, field_degree=d, numerator=count) or
                len(result['point']) != m or len(result['claims']) != claims):
                raise ValueError('batch corpus descriptor/accounting mismatch')
    print(f'gate batching: {len(cases)} shared decisions, all obligations and SC/RLC checked; no profile certified')


def small_corpus(root):
    for test, command in [
        ('', ['uv', 'run', '--locked', '--script', 'research/small-value/check_small_value.py', '--check-corpus']),
        ('tests::rejects_small_corpus_unchecked_narrowing', ['cargo', 'test', '-p', 'stele-sumcheck', '--example', 'corpus', '--locked', '--offline']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'small corpus drift or adapter failure: {result.stdout} {result.stderr}')
    sumcheck_corpus(root, 'research/small-value/corpus.jsonl')


def small_strategy(root):
    """A5 directed/seeded parity and actual original-value consumer rejection."""
    for package, target, tests in [
        ('stele-sumcheck', 'small', ('matches_reference_small_qm31',
         'matches_reference_small_om31', 'rejects_small_constructor_and_cached_instance',
         'matches_reference_small_zero_one_folds')),
        ('stele-sumcheck', 'small_reference', ('matches_reference_naive_small_qm31',
         'matches_reference_naive_small_om31')),
        ('stele-negative-controls', 'nc-0204', ('rejects_nc_0204',)),
    ]:
        result = subprocess.run(['cargo', 'test', '-p', package, '--test', target,
                                 '--locked', '--offline'], cwd=root, text=True, capture_output=True)
        if result.returncode or any(f'test {test} ... ok' not in result.stdout for test in tests):
            raise ValueError(f'small strategy parity/control mismatch: {result.stdout} {result.stderr}')
    print('gate small strategy: 1000 direct-reference cases per degree/field and NC-0204; independent decisions and measured costs pending')


def buffered_engine(root):
    """A6 engine buffers retain A1 bytes, consumers, capacities and preflight errors."""
    tests = ('matches_reference_buffered_qm31', 'matches_reference_buffered_om31',
             'accepts_empty_inputs_and_reuses_proof_and_byte_buffers',
             'rejects_buffer_shapes_before_mutating_transcript',
             'matches_reference_payloads_and_rejects_short_buffers_without_partial_writes',
             'rejects_buffered_false_sum_and_invalid_descriptor',
             'rejects_buffered_unused_final_value')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'buffers',
                             '--locked', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {test} ... ok' not in result.stdout for test in tests):
        raise ValueError(f'buffered A1 parity/consumer mismatch: {result.stdout} {result.stderr}')
    print('gate buffered A1: 1000 cases per degree/field, unchanged capacities, consumers and continuations')


def streaming_strategy(root):
    """A6 generic source/arena behavior; complete pipeline evidence remains open."""
    tests = ('matches_reference_streaming_qm31', 'matches_reference_streaming_om31',
             'accepts_workspace_smaller_than_dense_input', 'rejects_source_failures_and_capacity_overrun',
             'rejects_cached_instance_even_without_rounds', 'accepts_no_inputs_without_source_access',
             'rejects_source_failure_during_window_transition', 'matches_reference_zero_and_one_challenges',
             'matches_reference_window_suffix_contributions')
    result = subprocess.run(['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'streaming',
                             '--locked', '--offline'], cwd=root, text=True, capture_output=True)
    if result.returncode or any(f'test {test} ... ok' not in result.stdout for test in tests):
        raise ValueError(f'streaming A1 source/arena mismatch: {result.stdout} {result.stderr}')
    print('gate streaming A1: 1000 cases per degree/field; source visits, errors and arena limits')


def file_source(root):
    """Execute the opt-in file adapter and actual source-substitution control."""
    tests = ('matches_reference_file_source_qm31', 'matches_reference_file_source_om31',
             'rejects_malformed_files_and_preserves_existing_paths',
             'rejects_changed_length_on_replay_and_short_rows',
             'rejects_extra_bytes_after_open_and_keeps_original_handles',
             'accepts_empty_file_source_without_size_overflow')
    for command, names in [
        (['cargo', 'test', '-p', 'stele-sumcheck', '--features', 'std', '--test', 'file_source'], tests),
        (['cargo', 'test', '-p', 'stele-negative-controls', '--test', 'nc-0210'], ('rejects_nc_0210',)),
    ]:
        result = subprocess.run(command + ['--locked', '--offline'], cwd=root, text=True, capture_output=True)
        if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in names):
            raise ValueError(f'streaming file/control mismatch: {result.stdout} {result.stderr}')
    print('gate streaming files: canonical preparation/reads, preserved originals and NC-0210 in both fields')


def streaming_corpus(root):
    for test, command in [
        ('', ['uv', 'run', '--locked', '--script', 'research/streaming/check_windows.py', '--check-corpus']),
        ('tests::matches_reference_streaming_corpus_source_receipt',
         ['cargo', 'test', '-p', 'stele-sumcheck', '--features', 'std', '--example', 'corpus', '--locked', '--offline']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'streaming corpus drift or adapter failure: {result.stdout} {result.stderr}')
    sumcheck_corpus(root, 'research/streaming/corpus.jsonl', features=('std',))


def zerocheck(root):
    """Actual A3 bytes, all slice claims, SC phases and one-value controls."""
    for test, command in [
        ('matches_reference_zerocheck_bytes_and_accounting', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck', '--locked', '--offline']),
        ('matches_reference_naive_zerocheck_qm31', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck_reference', 'matches_reference_naive_zerocheck_qm31', '--locked', '--offline']),
        ('matches_reference_naive_zerocheck_om31', ['cargo', 'test', '-p', 'stele-sumcheck', '--test', 'zerocheck_reference', 'matches_reference_naive_zerocheck_om31', '--locked', '--offline']),
        ('zerocheck::rejects_zerocheck_binding_tampers', ['cargo', 'test', '-p', 'stele-negative-controls', '--lib', 'zerocheck::', '--locked', '--offline']),
        ('', ['uv', 'run', '--locked', '--script', 'research/zerocheck/check_zerocheck.py']),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or (test and f'test {test} ... ok' not in result.stdout):
            raise ValueError(f'zerocheck bytes/claims/accounting/control mismatch: {result.stdout} {result.stderr}')
    print('gate zerocheck: 130 both-field vectors, 1000 reference cases per degree/field, all slice claims, three SC phases and actual controls; no profile certified')


def zero_corpus(root):
    """Actual A3 public decisions, all original claims and ordered SC phases."""
    path = 'research/zerocheck/corpus.jsonl'
    outputs = []
    for command in [
        ['cargo', 'run', '-q', '-p', 'stele-sumcheck', '--example', 'zero_corpus', '--locked', '--offline', '--', path],
        ['uv', 'run', '--locked', '--script', 'research/zerocheck/check_zerocheck.py', '--verify-corpus', path],
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode:
            raise ValueError(f'zerocheck corpus producer failed: {result.stdout} {result.stderr}')
        outputs.append([json.loads(line) for line in result.stdout.splitlines()])
    cases = [json.loads(line) for line in (root / path).read_text().splitlines()]
    if not cases or outputs[0] != outputs[1] or len(outputs[0]) != len(cases):
        raise ValueError('zerocheck corpus decisions/claims/accounting mismatch')
    for case, result in zip(cases, outputs[0]):
        if result['name'] != case['name'] or result.get('error', 'accept') != case['expected']:
            raise ValueError('zerocheck corpus expected rejection mismatch')
        if case['expected'] == 'accept':
            i, d = case['instance'], case['field']
            delta = max([0] + [len(factors) for _, factors in i['terms']])
            j, s = i['m']-i['k'], 2**i['k']
            records = [dict(id=i['id'], phase=p, m=m, degree=degree, field_degree=d, numerator=m*degree)
                       for p, (m, degree) in enumerate([(j, 1), (int(i['k'] > 0), delta*(s-1)), (j, delta)])]
            if result['sc'] != records or len(result['claims']) != len(i['ids'])*s:
                raise ValueError('zerocheck corpus descriptor/accounting mismatch')
    print(f'gate zerocheck corpus: {len(cases)} shared decisions, all original claims and SC phases checked')


def merkle_vectors(root):
    """Execute actual authentication/KATs and check the independent candidate oracle."""
    for command, required in [
        (['cargo', 'test', '-p', 'stele-hash', '--test', 'merkle', '--locked', '--offline'],
         ('matches_reference_roots_paths_and_rejections',
          'rejects_descriptor_aliasing_and_invalid_shapes',
          'accepts_authenticated_child_root_and_rejects_wrong_child',
          'rejects_merkle_failures_with_usage')),
        (['uv', 'run', '--locked', '--script', 'research/merkle/check_merkle.py'], ()),
    ]:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
        if result.returncode or any(f'test {name} ... ok' not in result.stdout for name in required):
            raise ValueError(f'Merkle authentication/vector checks failed: {result.stdout} {result.stderr}')
    print('gate Merkle: actual roots, paths, batches and byte vectors checked; no PCS/profile certification')


def controls_layout(root):
    """Every standalone control source must be a declared Cargo test target."""
    suite = root / 'tests/negative-controls'
    manifest = tomllib.loads((suite / 'Cargo.toml').read_text())
    examples = [{'name':name,'path':f'examples/{name}.rs'} for name in ('field_pcs_bench','stacked_corpus','stacked_bench','lookup_corpus','lookup_bench')]
    dev = {'serde_json':'=1.0.154',
           'blake3':{'version':'=1.8.7','default-features':False}}
    dependencies = {f'stele-{n}':{'path':f'../../crates/stele-{n}'}
                    for n in ('reductions','pcs','lookup','sumcheck','field','hash','gkr','poly')}
    dependencies['stele-sumcheck']['features'] = ['std']
    if (manifest.get('example') != examples or manifest.get('dev-dependencies') != dev
            or manifest.get('dependencies') != dependencies
            or any(k in manifest for k in ('build-dependencies','target'))):
        raise ValueError('negative-controls: benchmark dependencies must remain dev-only and example exact')
    allowed = {'src/lib.rs', 'src/catalog.rs', 'src/main.rs', 'src/sumcheck.rs', 'src/batching.rs', 'src/zerocheck.rs', 'src/small.rs', 'src/streaming.rs', 'src/fraction.rs', 'src/fraction_transcript.rs', 'src/pcs.rs', 'src/pcs_a1.rs', 'fixtures/field-sources.txt', 'src/pcs_opening.rs', 'src/pcs_opening_field.rs', 'src/pcs_opening_continuation.rs', 'Cargo.toml'}
    allowed.update(example['path'] for example in examples)
    allowed.update(('src/stacked.rs', 'src/stacked_certified.rs',
                    'fixtures/stacked-public.sha256', 'fixtures/stacked-certified.sha256',
                    'lookup_corpus.py', 'lookup_corpus.py.lock', 'lookup_closed.py',
                    'src/lookup.rs', 'src/lookup_composer.rs', 'examples/support/lookup_verifier.rs'))
    for target in manifest.get('test', []):
        path = Path(target['path'])
        if path.is_absolute() or '..' in path.parts or path.suffix != '.rs':
            raise ValueError('invalid control test path')
        allowed.add(str(path))
    actual = {str(p.relative_to(suite)) for p in suite.rglob('*') if p.is_file()
              and p.suffix != '.md' and p.name != '.gitkeep'}
    if actual != allowed:
        raise ValueError(f'negative-controls: sources not wired to Cargo targets: {sorted(actual ^ allowed)}')


def rfc_status(root):
    """Code citations must resolve uniquely to an Accepted RFC."""
    statuses = {}
    for file in sorted((root / 'docs/rfcs').glob('RFC-*.md')):
        match = re.match(r'RFC-([0-9]{4})-', file.name)
        if not match:
            raise ValueError(f'malformed RFC filename: {file}')
        key = match[1]
        if key in statuses:
            raise ValueError(f'duplicate RFC-{key}')
        status = re.search(r'^Status: ([A-Za-z]+)', file.read_text(), re.MULTILINE)
        if not status:
            raise ValueError(f'RFC-{key} has no status')
        statuses[key] = status[1]
    references = 0
    sources = sorted(file for directory in ('crates', 'tests/negative-controls')
                     for file in (root / directory).rglob('*.rs'))
    if not sources:
        raise ValueError('no Rust sources found')
    for file in sources:
        for key in re.findall(r'RFC-([0-9]{4})', file.read_text()):
            if statuses.get(key) != 'Accepted':
                raise ValueError(f'{file.relative_to(root)} references RFC-{key}: '
                                 f'{statuses.get(key, "missing")}')
            references += 1
    print(f'gate rfc-status: checked {references} Accepted RFC references')


def docs_links(root):
    """Check local Markdown link file targets, without network requests."""
    files = [root / 'README.md']
    for directory in ('docs', 'agents'):
        files.extend((root / directory).rglob('*.md'))
    count = 0
    for file in files:
        # Inline Markdown links only; fenced examples are not document links.
        text = re.sub(r'```.*?```', '', file.read_text(), flags=re.DOTALL)
        for target in re.findall(r'\]\(([^)]+)\)', text):
            target = target.strip().split(' "', 1)[0].strip('<>')
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            path = unquote(url.path)
            resolved = (root / path.lstrip('/') if path.startswith('/') else file.parent / path)
            if not resolved.exists():
                raise ValueError(f'{file.relative_to(root)}: broken local link {target}')
            count += 1
    print(f'gate docs-links: checked {count} local file targets')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('gate', choices=(*OWNERS, 'native', 'rfc-status', 'docs-links'))
    args = parser.parse_args()
    try:
        if args.gate == 'rfc-status':
            rfc_status(ROOT)
        elif args.gate == 'docs-links':
            docs_links(ROOT)
        else:
            # The native job needs this union once. Standalone entry points
            # remain complete and do not consume cached success receipts.
            combined = args.gate == 'native'
            if combined or args.gate == 'negative-controls':
                controls_layout(ROOT)
            if combined or args.gate in ('negative-controls', 'soundness-accounting'):
                field_source_codec(ROOT)
                field_sources(ROOT)
            for gate in (('digest', 'negative-controls', 'soundness-accounting')
                         if combined else (args.gate,)):
                bootstrap_guard(ROOT, gate)
            if combined or args.gate == 'digest':
                native_encoder(ROOT)
            if combined or args.gate in ('negative-controls', 'soundness-accounting'):
                public_coefficients(ROOT)
                transcript_registry(ROOT)
                sumcheck_corpus(ROOT)
                fraction_reductions(ROOT)
                small_strategy(ROOT)
                small_corpus(ROOT)
                batch_instances(ROOT)
                batch_claims(ROOT)
                batch_corpus(ROOT)
                zerocheck(ROOT)
                zero_corpus(ROOT)
                buffered_engine(ROOT)
                streaming_strategy(ROOT)
                file_source(ROOT)
                streaming_corpus(ROOT)
                if combined or args.gate == 'negative-controls':
                    merkle_vectors(ROOT)
    except (OSError, ValueError, KeyError) as error:
        print(f'gate {args.gate}: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
