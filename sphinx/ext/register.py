# -*- coding: utf-8 -*-
"""
    sphinx.ext.register
    ~~~~~~~~~~~~~~~~~~~

    Allow register diagrams with field descriptions to be included
    in Sphinx-generated documents inline.

    :copyright: Copyright 2007-2018 by Varphone Wong <varphone@qq.com>.
    :license: BSD, see LICENSE for details.

    .. code:: example

       .. register:: AKA_FLAG
          :address: 0x2000_0000 0x0080
          :bits: 64
          :classes: colwidths-given altcolor
          :desc-tabular-colspec: >{\centering\arraybackslash}\X{1}{4} \X{3}{4}

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
          - "POWER ON" 0 0
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


class RegisterField(object):
    """
    Data to describe the register field.
    """

    def __init__(self, list_item):
        self.list_item = list_item
        # Split the field define
        fa = re.findall(r'[^"\s]\S*|".+?"', self.list_item[0].astext().strip())
        # Field name:
        if len(fa) > 0:
            self.name = fa[0].strip('\'\"')
        else:
            self.name = 'Undefined'
        # Field bit_range:
        if len(fa) > 1:
            self.bit_range = re.split('[-:,]', fa[1])
        else:
            self.bit_range = [0]
        # Field reset value:
        if len(fa) > 2:
            self.reset = fa[2]
        else:
            self.reset = ''


class register(nodes.General, nodes.Element):
    """
    A docutils node to use as a placeholder for the register.
    """

    default_address = ('0x0000_0000', '0x0000')
    default_bits = 32
    default_classes = ['nohline', 'novline', 'altcolor']
    default_desc = 'table'
    default_name = 'UNNAMED'

    def __init__(self, rawsource='', *children, **attributes):
        try:
            nodes.Element.__init__(self, rawsource, *children, **attributes)
        except:
            logger.warning(__("Unexpected error: %s") % sys.exc_info()[0])
            raise

        self.address = self.default_address
        self.bits = self.default_bits
        self.bullet_list = []
        self.classes = ['colwidths-given']
        self.desc = 'table'
        self.desc_tabular_widths = 'auto'
        self.fields = []
        self.name = self.default_name

    def get_nodes(self):
        return [self.make_address_title(), self]

    def set_options(self, options):
        self.address = options.get('address', self.address)
        self.bits = options.get('bits', self.bits)
        if options.get('classes'):
            self.classes += options.get('classes').split()
        else:
            self.classes += ['nohline', 'novline', 'altcolor']
        self.desc = options.get('desc', self.desc)
        self.desc_tabular_widths = options.get(
            'desc-tabular-widths', self.desc_tabular_widths)
        self.name = options.get('name', self.default_name)

        logger.warning("self.address = %r" % self.address)
        logger.warning("self.name = %r" % self.name)
        logger.warning("options.get('name') = %s" % options.get('name', self.default_name))

    def nested_parse(self, directive):
        # Parsing nested contents
        node = nodes.Element()
        directive.state.nested_parse(directive.content,
                                     directive.content_offset, node)
        if len(node.children) > 0:
            self.bullet_list = node[0]

        for li in self.bullet_list:
            self.fields.append(RegisterField(li))

    def make_address_title(self):
        text = 'Address = None'
        if len(self.address) == 2:
            text = __('Address = %s, Offset = %s') % (self.address[0], self.address[1])
        elif len(self.address) == 1:
            text = __('Address = %s') % self.address[0]

        return nodes.strong(text=text)


'''
        # Convert bullet list to fields
        self.fields = []
        self.fields = self.all_fields()

    def all_fields(self):
        a = []
        if self.bullet_list:
            for li in self.bullet_list:
                a.append(register_field(li))
        return a

    def address_title(self):
        node = nodes.strong(text='Address = 0x0000_0000, Offset = 0x0000')
        return node

    def description_table(self):
        header = (__('Field'), __('Description'))
        colwidths = (1, 3)
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
        thead += self._create_table_header_row(header)
        tgroup += thead
    
        tbody = nodes.tbody()
        for f in self.fields:
            tbody += self._create_table_desc_row(f)
        tgroup += tbody

        return table

    def _create_table_header_row(self, header):
        """
        Create a header row for the table node.
        """
        row = nodes.row()
        for cell in header:
            entry = nodes.entry()
            entry += nodes.paragraph(text=cell)
            row += entry
        return row

    def _create_table_desc_row(self, field):
        """
        Create a description row for the table node.
        """
        row = nodes.row()
        col = nodes.entry()
        bre = nodes.emphasis(text='-'.join(map(str, field.bit_range)))
        brp = nodes.paragraph()
        brp += bre
        col += brp
        col += nodes.paragraph(text=field.name)
        row += col

        col = nodes.entry()
        if len(field.list_item) < 2:
            col += nodes.paragraph(text='')
        else:
            for c in field.list_item[1:]:
                col += c
        row += col

        return row
'''


class register_field(nodes.General, nodes.Element):
    """
    A docutils node to use as a placeholder for the field of the register.
    """

    def __init__(self, list_item, rawsource='', *children, **attributes):
        try:
            nodes.Element.__init__(self, rawsource, *children, **attributes)
        except:
            logger.warning(__("Unexpected error: %s") % sys.exc_info()[0])
            raise
        self.list_item = list_item

        # Split the field define
        fa = re.findall(r'[^"\s]\S*|".+?"', self.list_item[0].astext().strip())
        # Field name:
        if len(fa) > 0:
            self.name = fa[0].strip('\'\"')
        else:
            self.name = 'Undefined'
        # Field bit_range:
        if len(fa) > 1:
            self.bit_range = re.split('[-:,]', fa[1])
        else:
            self.bit_range = [0]
        # Field reset value:
        if len(fa) > 2:
            self.reset = fa[2]
        else:
            self.reset = ''


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
        logger.warning("caption = %s" % self.caption)
        self.options['name'] = self.caption

        reg_node = register()
        reg_node.set_options(self.options)
        reg_node.nested_parse(self)

        return reg_node.get_nodes()
        '''
        if not self.options.get('address'):
            self.options['address'] = ('0x0000_0000', '0x0000')
        if not self.options.get('bits'):
            self.options['bits'] = 32
        if not self.options.get('desc'):
            self.options['desc'] = 'table'

        return [register()]
        '''
        node = aregister(self)

        # wrap the result in figure node
        #caption = self.options.get('caption')
        # if caption:
        #    node = figure_wrapper(self, node, caption)

        nr = []
        nr.append(node.address_title())
        nr.append(node)

        if self.options.get('desc') == 'table':
            if self.options.get('desc-tabular-colspec'):
                tcs = addnodes.tabular_col_spec()
                tcs['spec'] = self.options.get('desc-tabular-colspec')
                nr.append(tcs)
            t = node.description_table()
            title, messages = self.make_title()
            t.insert(0, title)
            nr.append(t)

        return nr

    def make_desc_table_title(self):
        if self.caption:
            text_nodes, messages = self.state.inline_text(self.caption,
                                                          self.lineno)
            title = nodes.title(self.caption, '', *text_nodes)
            (title.source,
             title.line) = self.state_machine.get_source_and_line(self.lineno)
        else:
            title = None
            messages = []
        return title, messages


def render_register_latex(self, node, code, options, prefix='register'):
    # type: (nodes.NodeVisitor, register, unicode, Dict, unicode) -> None
    pass
    #raise nodes.SkipNode


def html_visit_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    logger.warning("### self = %r, node = %r" % (self, node))
    for field in node.traverse(register_field):
        logger.info("children = %r" % field)

    raise nodes.SkipNode

# raise nodes.SkipNode


def html_depart_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    pass


def latex_visit_register(self, node):
    # type: (nodes.NodeVisitor, register) -> None
    #render_register_latex(self, node, node['code'], node['options'])
    logger.warning("### latex_visit_register %r, %r" % (self, node))
    logger.warning("node.name = %r, node.address = %r" % (node.name, node.address))
    self.body.append('\n')
    self.body.append('\\begin{register}{htbp}{%s}{}%% name=%s' % (node.name, node.name))
# \begin{register}{htbp}{Example}{0x250}% name=example
    s = r'''
\label{example}
\regfield{FIFO depth}{6}{58}{{random}}%
\regfield{Something}{4}{54}{1100}%
\regfield{Status}{21}{33}{{uninitialized}}%
\regfield{Enable}{1}{32}{1}%
\reglabel{Reset}%
\regnewline
\regfield{Counter}{10}{22}{{0x244}}% READ_ONLY
\regfield{Howdy}{5}{17}{1_1010}%
\regfield{Control}{1}{16}{-}%
\regfield{Hardfail}{1}{15}{1}%
\regfield{Data}{15}{0}{{uninitialized}}%
\reglabel{Reset}%
\regnewline
\end{register}
'''
    self.body.append('%s\n' % s)
    raise nodes.SkipNode


def latex_depart_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    logger.warning("### latex_depart_register %r, %r" % (self, node))


class demo_register(nodes.General, nodes.Element):

    def __init__(self, ext, rawsource='', *children, **attributes):
        try:
            nodes.Element.__init__(self, rawsource, *children, **attributes)
        except:
            logger.warning(__("Unexpected error: %s") % sys.exc_info()[0])
            raise

    def astext(self):
        return 'demo-register-1'


class DemoRegisterDirective(Directive):

    node_class = demo_register
    has_content = True
    required_arguments = 1
    optional_arguments = 0
    final_argument_whitespace = True

    def run(self):
        return [demo_register(self)]


def latex_visit_demo_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    logger.warning("### latex_visit_demo_register %r, %r" % (self, node))
    raise nodes.SkipNode


def latex_depart_demo_register(self, node):
    # type: (nodes.NodeVisitor, Register) -> None
    pass


"""    app.add_node(
        register,
        latex=(latex_visit_register, latex_depart_register))
    app.add_node(
        register_field,
        latex=(latex_visit_register_field, latex_depart_register_field))
    app.add_node(
        demo_register,
        latex=(latex_visit_demo_register, latex_depart_demo_register))
"""


def setup(app):
    # type: (Sphinx) -> Dict[unicode, Any]
    app.add_node(
        register,
        html=(html_visit_register, html_depart_register),
        latex=(latex_visit_register, latex_depart_register))

    app.add_directive('register', RegisterDirective)
    #app.add_directive('demo-register', DemoRegisterDirective)
    #app.add_config_value('graphviz_dot', 'dot', 'html')
    #app.add_config_value('graphviz_dot_args', [], 'html')
    #app.add_config_value('graphviz_output_format', 'png', 'html')
    return {'version': '1.0.0', 'parallel_read_safe': True}
