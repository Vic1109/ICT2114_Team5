'use strict';

// Run later with: node --test tests/test_report_editor_fidelity.js
// Uses the production inline editor script and Node's built-in test runner only.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const templatePath = path.join(__dirname, '..', 'config', 'templates', 'report_editor.html');
const template = fs.readFileSync(templatePath, 'utf8');
const editorScript = [...template.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(match => match[1]).find(script => script.includes('function addThreat('));
assert.ok(editorScript, 'production editor script must be present');

function decodeAttribute(value) {
    const entities = {'&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'"};
    return value.replace(/&(?:amp|lt|gt|quot|#39);/g, entity => entities[entity]);
}

function attribute(attributes, name) {
    const match = attributes.match(new RegExp('(?:^|\\s)' + name + '="([^"]*)"'));
    return match ? decodeAttribute(match[1]) : '';
}

// A small form-control fixture models the browser's selected-option fallback.
// Values come from addThreat's actual HTML; the fixture does not choose defaults.
class ThreatRow {
    constructor() {
        this.controls = new Map();
        this.markup = '';
    }

    set innerHTML(markup) {
        this.markup = markup;
        this.controls.clear();
        for (const match of markup.matchAll(/<input\b([^>]*data-threat-field="([^"]+)"[^>]*)>/g)) {
            this.controls.set(match[2], {value: attribute(match[1], 'value')});
        }
        for (const match of markup.matchAll(/<select\b([^>]*data-threat-field="([^"]+)"[^>]*)>([\s\S]*?)<\/select>/g)) {
            const options = [...match[3].matchAll(/<option\b([^>]*)>([\s\S]*?)<\/option>/g)]
                .map(option => ({
                    value: attribute(option[1], 'value'),
                    selected: /(?:^|\s)selected(?:\s|=|$)/.test(option[1])
                }));
            const selected = options.find(option => option.selected) || options[0];
            this.controls.set(match[2], {
                options,
                _value: selected ? selected.value : '',
                get value() { return this._value; },
                set value(value) {
                    this._value = options.some(option => option.value === value) ? value : '';
                }
            });
        }
    }

    querySelector(selector) {
        const match = selector.match(/^\[data-threat-field="([^"]+)"\]$/);
        assert.ok(match, `unexpected row selector: ${selector}`);
        assert.ok(this.controls.has(match[1]), `missing form control: ${match[1]}`);
        return this.controls.get(match[1]);
    }
}

function plain(value) {
    return JSON.parse(JSON.stringify(value));
}

function editorFor(report) {
    const rows = [];
    const elements = new Map();
    const document = {
        getElementById(id) {
            if (!elements.has(id)) elements.set(id, {value: '', style: {}, textContent: '', innerHTML: ''});
            return elements.get(id);
        },
        querySelectorAll(selector) {
            if (selector === '#threatsBody tr') return rows;
            if (selector === '#findingsList input' || selector === '#recommendationsList input') return [];
            if (selector === '.mitre-item.selected') return [];
            throw new Error(`unexpected document selector: ${selector}`);
        },
        addEventListener() {}
    };
    elements.set('threatsBody', {insertRow() {
        const row = new ThreatRow();
        rows.push(row);
        return row;
    }});
    const context = vm.createContext({document, window: {}, confirm: () => true});
    const script = editorScript
        .replace(/\{\{\s*report_id\s*\|\s*tojson\s*\}\}/g, JSON.stringify('fixture-report'))
        .replace(/\{\{\s*report_data\s*\|\s*tojson\s*\}\}/g, JSON.stringify(report));
    vm.runInContext(script, context, {filename: templatePath});
    // Form tests never invoke fetch, preview rendering, onload, or auto-save.
    context.updatePreview = () => {};
    context.loadReportData();
    return {
        context, rows, elements,
        collect: () => plain(context.collectFormData()),
        setField(row, field, value) { row.querySelector(`[data-threat-field="${field}"]`).value = value; }
    };
}

function threat(overrides = {}) {
    return {
        ip: '203.0.113.8', type: 'Destination', country: 'Unknown',
        direction: 'outbound', activity: 'Connection observed', severity: 'HIGH',
        confidence: 'Medium', count: '2', ...overrides
    };
}

test('untouched Destination/outbound/Medium survives initialization and collection', () => {
    const editor = editorFor({threats: [threat()]});
    const collected = editor.collect().threats[0];
    assert.equal(collected.type, 'Destination');
    assert.equal(collected.direction, 'Outbound');
    assert.equal(collected.confidence, 'Medium');
    assert.equal(editor.collect().report_id, 'fixture-report');
    assert.equal(editor.rows[0].controls.get('direction').value, 'Outbound');
});

test('recognized direction case normalizes without changing custom evidence', () => {
    for (const [source, expected] of [['INBOUND', 'Inbound'], [' outbound ', 'Outbound'], ['lAtErAl', 'Lateral']]) {
        const editor = editorFor({threats: [threat({direction: source})]});
        assert.equal(editor.collect().threats[0].direction, expected);
    }
    for (const source of ['Not established', 'Bidirectional', 'toString', '__proto__']) {
        const editor = editorFor({threats: [threat({direction: source})]});
        assert.equal(editor.collect().threats[0].direction, source);
    }
});

test('all original role and confidence values remain selectable and escaped', () => {
    const value = '<Observed & "unrated">';
    const editor = editorFor({threats: [threat({type: value, confidence: value})]});
    assert.equal(editor.collect().threats[0].type, value);
    assert.equal(editor.collect().threats[0].confidence, value);
    assert.ok(editor.rows[0].markup.includes('&lt;Observed &amp; &quot;unrated&quot;&gt;'));
    assert.ok(!editor.rows[0].markup.includes('value="<Observed'));
    for (const confidence of ['Low', 'low', 'Unrated', '', null]) {
        const fixture = editorFor({threats: [threat({confidence})]});
        assert.equal(fixture.collect().threats[0].confidence, confidence);
    }
});

test('missing fields and a new threat receive no asserted type, direction, or confidence', () => {
    const input = threat();
    for (const field of ['type', 'direction', 'confidence']) delete input[field];
    const editor = editorFor({threats: [input]});
    for (const field of ['type', 'direction', 'confidence']) {
        assert.equal(editor.rows[0].controls.get(field).value, '');
        assert.equal(Object.hasOwn(editor.collect().threats[0], field), false);
    }
    editor.context.addThreat();
    editor.setField(editor.rows[1], 'ip', '198.51.100.4');
    for (const field of ['type', 'direction', 'confidence']) {
        assert.equal(Object.hasOwn(editor.collect().threats[1], field), false);
    }
});

test('reviewer changes replace the original fields, including explicit clearing', () => {
    const editor = editorFor({threats: [threat()]});
    editor.setField(editor.rows[0], 'type', 'Source');
    editor.setField(editor.rows[0], 'direction', 'Inbound');
    editor.setField(editor.rows[0], 'confidence', 'Low');
    const collected = editor.collect().threats[0];
    assert.equal(collected.type, 'Source');
    assert.equal(collected.direction, 'Inbound');
    assert.equal(collected.confidence, 'Low');
    editor.setField(editor.rows[0], 'confidence', '');
    assert.equal(editor.collect().threats[0].confidence, '');
});

test('removing or reordering rows keeps each surviving row linked to its evidence', () => {
    const editor = editorFor({threats: [
        threat({confidence: 'Low', evidence_ref: 'row-a'}),
        threat({ip: '198.51.100.4', type: 'Source', direction: 'Inbound', confidence: 'Unrated', evidence_ref: 'row-b'})
    ]});
    editor.rows.reverse();
    assert.equal(editor.collect().threats[0].evidence_ref, 'row-b');
    editor.rows.pop();
    assert.equal(editor.collect().threats[0].type, 'Source');
    assert.equal(editor.collect().threats[0].confidence, 'Unrated');
});

test('original MITRE evidence metadata survives catalog selection and clear-all', () => {
    const metadata = {
        mitre_techniques: [{id: 'T1059', name: 'Command interpreter'}],
        mitre_original_techniques: ['T1059'],
        mitre_technique_details: {T1059: {evidence_classes: ['historical_only'], name: 'Command interpreter'}},
        mitre_selection_edited: false
    };
    const editor = editorFor(metadata);
    assert.deepEqual(editor.collect().mitre_technique_details, metadata.mitre_technique_details);
    assert.equal(editor.collect().mitre_selection_edited, false);
    assert.ok(editor.elements.get('selectedTechniques').textContent.includes('Historical CTI only'));
    const button = {classList: {add() {}, remove() {}}, setAttribute() {}};
    editor.context.toggleMITRE('T1071', button);
    assert.equal(editor.collect().mitre_selection_edited, true);
    assert.deepEqual(editor.collect().mitre_modified_techniques, ['T1071']);
    assert.ok(editor.elements.get('selectedTechniques').textContent.includes('Analyst added; evidence not established'));
    assert.deepEqual(editor.collect().mitre_original_techniques, ['T1059']);
    editor.context.clearAllMITRE();
    assert.deepEqual(editor.collect().mitre_techniques, []);
    assert.deepEqual(editor.collect().mitre_modified_techniques, ['T1059', 'T1071']);
    assert.deepEqual(editor.collect().mitre_technique_details, metadata.mitre_technique_details);
});

test('legacy MITRE payloads do not acquire an empty original baseline', () => {
    const editor = editorFor({mitre_techniques: ['T1059']});
    assert.equal(Object.hasOwn(editor.collect(), 'mitre_original_techniques'), false);
    assert.equal(Object.hasOwn(editor.collect(), 'mitre_technique_details'), false);
    assert.equal(editor.collect().mitre_selection_edited, false);
});

test('remove and re-add tracks the changed technique while preserving its evidence', () => {
    const details = {T1059: {evidence_classes: ['inferred_current']}};
    const editor = editorFor({
        mitre_techniques: ['T1059', 'T1071'],
        mitre_original_techniques: ['T1059', 'T1071'],
        mitre_technique_details: details,
        mitre_modified_techniques: ['T1082']
    });
    const button = {classList: {add() {}, remove() {}}, setAttribute() {}};
    editor.context.toggleMITRE('T1059', button);
    editor.context.toggleMITRE('T1059', button);
    assert.deepEqual(editor.collect().mitre_modified_techniques, ['T1059', 'T1082']);
    assert.deepEqual(editor.collect().mitre_technique_details, details);
    assert.ok(editor.collect().mitre_techniques.some(technique => technique.id === 'T1059'));
});
