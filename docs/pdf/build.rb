#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Build state-of-the-art PDF documentation from the PROMÉTHÉE AsciiDoc wiki.
# Produces two combined manuals in docs/pdf/:
#   - PROMETHEE-Guide-utilisateur.pdf   (FR user guide, 14 chapters)
#   - PROMETHEE-Guide-developpeur.pdf    (FR dev guide, 1 chapter)
#
# The wiki submodule (wiki/) is NEVER modified: content is staged into a build
# dir, cross-references are rewritten to in-document anchors, and master docs
# include the staged pages with a level offset so each page's `= Title` becomes
# a `==` chapter.
#
# ponytail: network dep on kroki.io for the 4 mermaid PNGs (advanced_auditing,
# lgpo, safer, secedit). mmdc is unusable on aarch64 (puppeteer ships an x86
# chrome). If the build goes offline or into CI, pre-render the 4 PNGs once and
# replace the [mermaid] blocks with image:: refs during staging.
#
# Run: ruby docs/pdf/build.rb
# Validate: ruby docs/pdf/build.rb --check

require 'fileutils'
require 'pathname'
require 'open3'
require 'tmpdir'
require 'csv'

ROOT    = File.expand_path('../../..', __FILE__)
WIKI_FR = File.join(ROOT, 'wiki', 'FR')
OUTDIR  = File.expand_path('..', __FILE__)
BUILD   = File.join(OUTDIR, '.build')
THEME   = File.join(OUTDIR, 'theme.yml')
LOGO    = File.join(ROOT, 'logo.svg')
# asciidoctor include targets cannot contain spaces; stage into spaceless paths.
GEM_BIN = File.join(Gem.user_dir, 'bin')

def stage_rel(rel)
  rel.gsub(' ', '-')
end

ENV['PATH'] = "#{GEM_BIN}:#{ENV['PATH']}"

VERSION = 'v1.0.0'
DATE    = Time.now.strftime('%Y-%m-%d')
AUTHOR  = 'Antoine Raulin'

# wiki/FR-relative path -> chapter anchor id
ANCHORS = {
  '01-Guide utilisateur/01-Démarrage.asciidoc'                          => 'guide-demarrage',
  '01-Guide utilisateur/02-Format-CSV.asciidoc'                          => 'guide-format-csv',
  '01-Guide utilisateur/03-Méthodes.asciidoc'                           => 'guide-methodes',
  '01-Guide utilisateur/04-Méthodes/01-advanced_auditing.asciidoc'      => 'meth-advanced-auditing',
  '01-Guide utilisateur/04-Méthodes/02-appx_package.asciidoc'           => 'meth-appx-package',
  '01-Guide utilisateur/04-Méthodes/03-firewall.asciidoc'              => 'meth-firewall',
  '01-Guide utilisateur/04-Méthodes/04-lgpo.asciidoc'                  => 'meth-lgpo',
  '01-Guide utilisateur/04-Méthodes/05-local_group.asciidoc'            => 'meth-local-group',
  '01-Guide utilisateur/04-Méthodes/06-local_user.asciidoc'             => 'meth-local-user',
  '01-Guide utilisateur/04-Méthodes/07-safer.asciidoc'                 => 'meth-safer',
  '01-Guide utilisateur/04-Méthodes/08-secedit.asciidoc'               => 'meth-secedit',
  '01-Guide utilisateur/04-Méthodes/09-service.asciidoc'                => 'meth-service',
  '01-Guide utilisateur/04-Méthodes/10-windows_capability.asciidoc'    => 'meth-windows-capability',
  '01-Guide utilisateur/04-Méthodes/11-windows_optional_feature.asciidoc' => 'meth-windows-optional-feature',
  '02-Guide développeur/01-Ajouter-une-méthode.asciidoc'               => 'dev-ajouter-methode'
}

USER_GUIDE = [
  '01-Guide utilisateur/01-Démarrage.asciidoc',
  '01-Guide utilisateur/02-Format-CSV.asciidoc',
  '01-Guide utilisateur/03-Méthodes.asciidoc',
  '01-Guide utilisateur/04-Méthodes/01-advanced_auditing.asciidoc',
  '01-Guide utilisateur/04-Méthodes/02-appx_package.asciidoc',
  '01-Guide utilisateur/04-Méthodes/03-firewall.asciidoc',
  '01-Guide utilisateur/04-Méthodes/04-lgpo.asciidoc',
  '01-Guide utilisateur/04-Méthodes/05-local_group.asciidoc',
  '01-Guide utilisateur/04-Méthodes/06-local_user.asciidoc',
  '01-Guide utilisateur/04-Méthodes/07-safer.asciidoc',
  '01-Guide utilisateur/04-Méthodes/08-secedit.asciidoc',
  '01-Guide utilisateur/04-Méthodes/09-service.asciidoc',
  '01-Guide utilisateur/04-Méthodes/10-windows_capability.asciidoc',
  '01-Guide utilisateur/04-Méthodes/11-windows_optional_feature.asciidoc'
].freeze
DEV_GUIDE = [
  '02-Guide développeur/01-Ajouter-une-méthode.asciidoc'
].freeze

# staged (spaceless) rel -> anchor id
STAGE_ANCHOR = ANCHORS.to_h { |rel, anchor| [stage_rel(rel), anchor] }

# Rewrite intra-wiki xref:file.asciidoc[Label] (and xref:file.asciidoc#frag[Label])
# into xref:#anchor[Label], resolved relative to the current file's directory.
def rewrite_xrefs(text, staged_file, fr_root)
  text.gsub(/xref:([^\[]+)\[([^\]]*)\]/) do
    orig = Regexp.last_match(0)
    target, label = Regexp.last_match(1), Regexp.last_match(2)
    path, frag = target.split('#', 2)
    # external or already-fragment-only xrefs: leave untouched
    next orig if path.empty? || path =~ %r{^https?://} || path =~ %r{^[A-Za-z]+://}
    resolved = File.expand_path(path, File.dirname(staged_file))
    rel = Pathname.new(resolved).relative_path_from(Pathname.new(fr_root)).to_s
    anchor = STAGE_ANCHOR[rel]
    if anchor.nil?
      warn "  ! unresolved xref target: #{path} (-> #{rel}) in #{staged_file}"
      next orig
    end
    dest = frag ? "##{frag}" : "##{anchor}"
    "xref:#{dest}[#{label}]"
  end
end

# Inject [[anchor]] directly above the first `= ` heading in a staged file.
def inject_anchor(text, anchor)
  return text if text =~ /\A\s*\[\[#{anchor}\]\]/
  text.sub(/^(= )/, "[[#{anchor}]]\n\\1")
end

# In each method page's `=== Exemple` section the same CSV row appears twice:
# once as a [source,csv] block and once as a collapsible "Exemple de CSV brut".
# Convert the [source,csv] block to a 2-column (Colonne | Valeur) table and drop
# the collapsible duplicate. Pages whose example is already a table (advanced_auditing)
# only lose the collapsible. ponytail: regex transform on a consistent wiki pattern.
def dedup_csv_example(text)
  # Remove the collapsible raw-CSV block entirely.
  text.gsub!(/\.Exemple de CSV brut\n\[%collapsible\]\n====\n.*?\n====\n/m, '')
  # Convert a [source,csv] block (header + single row) into a 2-column table.
  text.gsub!(/\[source,csv\]\n----\n(.*?)\n----/m) do
    body = Regexp.last_match(1)
    rows = CSV.parse(body)
    next Regexp.last_match(0) if rows.size < 2
    header, row = rows[0], rows[1]
    out = String.new("[options=\"header\"]\n|===\n| Colonne | Valeur\n")
    header.each_with_index do |col, i|
      out << "| #{col} | #{row[i] || ''}\n"
    end
    out << "|==="
    out
  end
  text
end

def stage
  FileUtils.rm_rf(BUILD)
  FileUtils.mkdir_p(BUILD)
  fr_root = File.join(BUILD, 'fr')
  FileUtils.mkdir_p(fr_root)
  # Copy the dotfile asset dir explicitly (globs that skip dotfiles would miss it).
  FileUtils.cp_r(File.join(WIKI_FR, '.assets'), File.join(fr_root, '.assets'))
  # Copy each asciidoc page to a spaceless staged path, inject anchor, rewrite xrefs.
  ANCHORS.each do |rel, anchor|
    src = File.join(WIKI_FR, rel)
    raise "wiki source missing: #{src}" unless File.exist?(src)
    dst = File.join(fr_root, stage_rel(rel))
    FileUtils.mkdir_p(File.dirname(dst))
    FileUtils.cp(src, dst)
    text = File.read(dst, encoding: 'UTF-8')
    text = inject_anchor(text, anchor)
    text = rewrite_xrefs(text, dst, fr_root)
    text = dedup_csv_example(text)
    # :csv-dir: is relative to the page's own dir on GitLab; in the combined
    # master the base_dir is .build/, so make it absolute to the staged assets.
    if rel.end_with?('01-advanced_auditing.asciidoc')
      text.sub!(/^:csv-dir:.*$/, ":csv-dir: #{File.join(fr_root, '.assets', 'advanced_auditing')}")
    end
    File.write(dst, text, encoding: 'UTF-8')
  end
end

def master_header(title)
  <<~ADOC
    = #{title}
    :doctype: article
    :toc: auto
    :toclevels: 2
    :lang: fr
    :author: #{AUTHOR}
    :revnumber: #{VERSION}
    :revdate: #{DATE}
    :source-highlighter: rouge
    :icons: font
    :allow-uri-read:
    :kroki-fetch:
    :kroki-default-format: png
    :pdf-theme: #{THEME}
  ADOC
end

def build_master(name, title, pages)
  out = File.join(BUILD, "#{name}.adoc")
  body = String.new
  pages.each do |rel|
    body << "\ninclude::fr/#{stage_rel(rel)}[leveloffset=+1]\n"
    # Unset attrs leaked by advanced_auditing (:csv-dir:, :table-cols:).
    if rel.end_with?('01-advanced_auditing.asciidoc')
      body << "\n:csv-dir!:\n:table-cols!:\n"
    end
  end
  File.write(out, master_header(title) + "\n" + body, encoding: 'UTF-8')
  out
end

def render(master, output_pdf)
  cmd = %w[asciidoctor-pdf -r asciidoctor-kroki --failure-level=WARN]
  cmd += ['-a', 'allow-uri-read', '-a', 'kroki-fetch=true', '-a', 'kroki-default-format=png']
  cmd += [master, '-o', output_pdf]
  stdout, status = Open3.capture2e(*cmd)
  puts stdout unless stdout.empty?
  raise "asciidoctor-pdf failed (#{status}) for #{master}" unless status.success?
  output_pdf
end

def check(pdf)
  begin
    require 'pdf/reader'
  rescue LoadError
    warn 'pdf-reader not available; skipping checks.'
    return
  end
  reader = PDF::Reader.new(pdf)
  puts "\n--- check: #{File.basename(pdf)} ---"
  puts "pages: #{reader.page_count}"
  cover = reader.pages.first.text
  puts "cover title: #{cover.lines.reject(&:empty?).first(3).map(&:strip).join(' / ')}"
  # accent sanity: ensure a French accented word is present and not mojibake.
  sample = reader.pages.map(&:text).join
  accented = sample.match?(/[éèêëàâôùç]/) ? 'OK (FR diacritics present)' : 'FAIL (no FR diacritics)'
  puts "accent check: #{accented}"
  # Count clickable Link annotations across pages (xref + external links).
  click = 0
  reader.pages.each do |p|
    annots = p.attributes[:Annots]
    next unless annots
    annots.each do |ref|
      obj = reader.objects[ref]
      click += 1 if obj.is_a?(Hash) && obj[:Subtype] == :Link
    end
  end
  puts "clickable link annotations: #{click}"
  puts "ok"
end

def main
  Dir.chdir(ROOT)
  stage
  ug = build_master('user-guide', 'PROMÉTHÉE — Guide utilisateur', USER_GUIDE)
  dg = build_master('dev-guide',  'PROMÉTHÉE — Guide développeur', DEV_GUIDE)
  ug_pdf = File.join(OUTDIR, 'PROMETHEE-Guide-utilisateur.pdf')
  dg_pdf = File.join(OUTDIR, 'PROMETHEE-Guide-developpeur.pdf')
  render(ug, ug_pdf)
  render(dg, dg_pdf)
  puts "\nBuilt:"
  puts "  #{ug_pdf}"
  puts "  #{dg_pdf}"
  check(ug_pdf) if ARGV.include?('--check')
  check(dg_pdf) if ARGV.include?('--check')
end

main