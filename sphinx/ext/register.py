# -*- coding: utf-8 -*-
r"""
    sphinx.ext.register
    ~~~~~~~~~~~~~~~~~~~

    Allow register diagrams with field descriptions to be included
    in Sphinx-generated documents inline.

    :copyright: Copyright 2007-2018 by Varphone Wong <varphone@qq.com>.
    :license: BSD, see LICENSE for details.

    Example::

       .. register:: AKA_FLAG
          :address: 0x2000_0000 0x0080
          :bits: 64
          :classes: colwidths-given altcolor
          :desc-tabular-colspec: >{\centering\arraybackslash}\X{1}{10} \X{1}{10} \X{2}{10} \X{6}{10}

          - FLAG_K 7-5 110

            Flag K to xxxxx

            - 000 xxxxx
            - 001 xxxxx
            - 010 xxxxx
            - 011 xxxxx
            - 100 xxxxx
            - 101 xxxxx
            - 111 xxxxx

          - FLAG_B 4-2 111
          - "POWOER OFF" 1 0
          - "POWER ON" 0 0 R
"""

from docutils import nodes
from docutils.parsers.rst import Directive, directives

import re
import sys
from sphinx import addnodes
from sphinx.util import logging
from sphinx.directives.patches import ListTable
from sphinx.ext.graphviz import figure_wrapper
from sphinx.locale import __

if False:
    # For type annotation
    from typing import Any, Dict, Iterable, List  # NOQA
    from sphinx.application import Sphinx  # NOQA
    from sphinx.environment import BuildEnvironment  # NOQA

logger = logging.getLogger(__name__)


class RegisterField:
    """
    Object of the register field.
    """

    default_access = 'RW'
    default_reset = '-'

    def __init__(self, list_item=[], rawsource=''):
        self.list_item = list_item
        self.rawsource = rawsource

        if not self.rawsource:
            self.rawsource = self.list_item[0].astext().strip()

        # Split the field define
        # The r'[^"\s]\S*|".+?"' only supports "field name" format
        # The r'''[^'"\[\s]\S*|['"\[].+?['"\]]''' supports:
        #    'field name' or "field name" or [field name] formats
        fa = re.findall(r'''[^'"\[\s]\S*|['"\[].+?['"\]]''', self.rawsource)

        # Must be 2 parts specfied
        if len(fa) < 2:
            raise ValueError(
                __('The field: \"%s\" is bad format!\n'
                   '  expected: \"{NAME} {MSB}-{LSB} {RESET} {R|W|RW|NA}\"') %
                self.rawsource)

        # Field name (required):
        if len(fa) > 0:
            self.name = fa[0].strip('\'\"')

        # Field bit_range (required):
        if len(fa) > 1:
            self.parse_bit_range(fa[1])

        # Field reset or access (optional):
        self.access = self.default_access
        self.reset = self.default_reset

        if len(fa) > 2:
            self.parse_access_or_reset(fa[2:])

    def parse_bit_range(self, str):

        # Strip whitespace and quotes
        s = str.strip(' []\'\"')

        # Check format
        if not re.match(r'^\d+(\s*[-:,\s]+\s*\d+)?$', s):
            raise ValueError(
                __('The bit range part: "%s" is bad format!\n'
                   '  expected: "{MSB}-{LSB}"') % str)

        # Support flex delimiters
        # MSB-LSB, MSB:LSB, MSB,LSB, [MSB LSB], "MSB : LSB"
        self.bit_range = list(map(int, re.split(r'[-:,\s]+', s)))

        # Auto fix single param mode
        if len(self.bit_range) == 1:
            self.bit_range.append(self.bit_range[0])

        # Sort to MSB-LSB orders
        self.bit_range.sort(reverse=True)

        # Alias
        self.length = self.bit_range[0] - self.bit_range[1] + 1
        self.start = self.bit_range[0]

    def parse_access_or_reset(self, ar):
        for a in ar:
            s = a.strip(' []\'\"')
            if 'R' in s or 'W' in s or 'NA' in s:
                self.access = s
            else:
                self.reset = s


class Register:
    """
    Object of the register.
    """

    default_address = ('0x0000_0000', '0x0000')
    default_bits = 32
    default_classes = ['colwidths-given', 'nohline', 'novline', 'altcolor']
    default_desc = 'table'
    default_desc_tabular_widths = 'auto'
    default_name = 'UNNAMED'

    def __init__(self):
        self.address = self.default_address
        self.bits = self.default_bits
        self.bullet_list = []
        self.classes = self.default_classes
        self.desc = self.default_desc
        self.desc_tabular_widths = self.default_desc_tabular_widths
        self.fields = []
        self.name = self.default_name
        self.title = None

    def fix_missing(self):
        bit_max = self.fields[0].bit_range[0]
        bit_min = self.fields[-1].bit_range[1]

        if bit_max < self.bits - 1:
            if self.bits - bit_max > 2:
                s = 'Reserved %i-%i NA' % (self.bits - 1, bit_max + 1)
            else:
                s = 'Reserved %i NA' % (self.bits - 1)
            f = RegisterField(rawsource=s)
            self.fields.insert(0, f)

        if bit_min > 0:
            if bit_min > 1:
                s = 'Reserved %i-%i NA' % (bit_min - 1, 0)
            else:
                s = 'Reserved 0 NA'
            f = RegisterField(rawsource=s)
            self.fields.append(f)

    def get_nodes(self):
        ret_nodes = []

        ret_nodes.append(self.make_address_title())
        reg_node = register()
        reg_node['register'] = self

        ret_nodes.append(reg_node)

        if self.desc == 'table':
            if self.title:
                ret_nodes.append(self.title)
            ret_nodes.append(self.make_desc_table())

        return ret_nodes

    def set_options(self, options):
        self.address = options.get('address', self.default_address)
        self.bits = int(options.get('bits', self.default_bits))
        if options.get('classes'):
            self.classes = options.get('classes').split()
        else:
            self.classes = self.default_classes
        self.desc = options.get('desc', self.default_desc)
        self.desc_tabular_widths = options.get(
            'desc-tabular-widths', self.default_desc_tabular_widths)
        self.name = options.get('name', self.default_name)

    def set_title(self, title):
        self.title = title

    def nested_parse(self, directive):
        # Parsing nested contents
        node = nodes.Element()
        directive.state.nested_parse(directive.content,
                                     directive.content_offset, node)
        if len(node.children) > 0:
            self.bullet_list = node[0]

        # Convert list item to RegisterField
        for li in self.bullet_list:
            self.fields.append(RegisterField(li))

        # Sort the fields with descend of the start offset
        self.fields.sort(key=lambda x: x.start, reverse=True)

        self.fix_missing()

    def make_address_title(self):
        text = 'Address = None'
        if len(self.address) == 2:
            text = __('Address = %s, Offset = %s') % \
                (self.address[0], self.address[1])
        elif len(self.address) == 1:
            text = __('Address = %s') % self.address[0]

        return nodes.emphasis(text=text)

    def create_desc_table_header_row(self, header):
        """
        Create a header row for the table node.
        """
        row = nodes.row()
        for cell in header:
            entry = nodes.entry()
            entry += nodes.paragraph(text=cell)
            row += entry
        return row

    def create_desc_table_field_row(self, field):
        """
        Create a description row for the table node.
        """
        row = nodes.row()

        # Bits
        bits_col = nodes.entry()
        row += bits_col
        if field.length == 1:
            bits_col += nodes.emphasis(text='[%s]' % field.start)
        else:
            bits_col += nodes.emphasis(text='[%s]' % ':'.join(map(str, field.bit_range)))

        # Access
        access_col = nodes.entry()
        row += access_col
        access_col += nodes.emphasis(text=field.access)

        # Name
        name_col = nodes.entry()
        row += name_col
        name_col += nodes.paragraph(text=field.name)

        # Description
        desc_col = nodes.entry()
        row += desc_col
        if len(field.list_item) < 2:
            desc_col += nodes.paragraph(text='')
        else:
            for c in field.list_item[1:]:
                desc_col += c

        return row

    def make_desc_table(self):
        header = (__('Bits'), __('Access'), __('Name'), __('Description'))
        colwidths = (1, 1, 2, 6)
        if self.desc_tabular_widths != 'auto':
            colwidths = self.desc_tabular_widths.split()

        table = nodes.table()
        table['align'] = 'center'
        table['classes'] += self.classes

        tgroup = nodes.tgroup(cols=len(header))
        for colwidth in colwidths:
            tgroup += nodes.colspec(colwidth=colwidth)
        table += tgroup

        thead = nodes.thead()
        thead += self.create_desc_table_header_row(header)
        tgroup += thead

        tbody = nodes.tbody()
        for f in self.fields:
            tbody += self.create_desc_table_field_row(f)
        tgroup += tbody

        return table


class register(nodes.General, nodes.Element):
    """
    A docutils node to use as a placeholder for the register.
    """
    pass


def yesno(argument):
    return directives.choice(argument, ('yes', 'no'))


def address(argument):
    return argument.split()


def desc_style(argument):
    return directives.choice(argument, ('none', 'list', 'table'))


class RegisterDirective(Directive):
    """
    Directive to insert arbitrary register markup.
    """

    node_class = register
    has_content = True
    required_arguments = 1
    optional_arguments = 0
    final_argument_whitespace = True
    option_spec = {
        'address': address,
        'bits': directives.positive_int,
        'caption': directives.unchanged,
        'classes': directives.unchanged,
        'desc': desc_style,
        'desc-tabular-colspec': directives.unchanged,
        'desc-tabular-widths': directives.unchanged,
    }

    def run(self):
        # type: () -> List[nodes.Node]
        self.caption = self.options.get('caption', self.arguments[0])
        self.options['name'] = self.caption

        reg = Register()
        reg.set_options(self.options)
        reg.nested_parse(self)

        return reg.get_nodes()

    def make_title(self):
        if self.caption:
            state = self.state
            state_machine = self.state_machine
            text_nodes, messages = state.inline_text(self.caption,
                                                     self.lineno)
            title = nodes.title(self.caption, '', *text_nodes)
            (title.source,
             title.line) = state_machine.get_source_and_line(self.lineno)
        else:
            title = None
            messages = []
        return title, messages


def html_visit_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None

    raise nodes.SkipNode


def html_depart_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    pass


def latex_visit_register(self, node):
    # type: (nodes.NodeVisitor, register) -> None
    reg = node['register']

    logger.warning("latex_visit_register(%r,%r)" % (self, node))

    self.body.append('\n')
    self.body.append('\\begin{register}{H}{%s}{}%% name=%s\n' %
                     (reg.name, reg.name))
    self.body.append('\\label{%s}\n' % reg.name)
    for f in reg.fields:
        latex_name = f.name.replace('_', '\\_').replace('-', '\\-')
        if reg.bits == 64:
            self.body.append('\\regfield{%s}{%i}{%i}{%s}%%\n' %
                             (latex_name, f.length, f.start, f.reset))
            if f.start == 32:
                self.body.append('\\reglabel{%s}%%\n' % __('Reset'))
                self.body.append('\\regnewline\n')
        elif reg.bits == 32:
            self.body.append('\\regfield{%s}{%i}{%i}{%s}%%\n' %
                             (latex_name, f.length, f.start, f.reset))

    self.body.append('\\reglabel{%s}%%\n' % __('Reset'))
    self.body.append('\\regnewline\n')
    self.body.append('\\end{register}\n')

    raise nodes.SkipNode


def latex_depart_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    pass


def setup(app):
    # type: (Sphinx) -> Dict[unicode, Any]
    app.add_node(
        register,
        html=(html_visit_register, html_depart_register),
        latex=(latex_visit_register, latex_depart_register))

    app.add_directive('register', RegisterDirective)
    return {'version': '1.0.0', 'parallel_read_safe': True}
