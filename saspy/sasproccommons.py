#
# Copyright SAS Institute
#
#  Licensed under the Apache License, Version 2.0 (the License);
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
import logging
import re
from saspy.sasresults import SASresults
# from pdb import set_trace as bp


class SASProcCommons:
    def __init__(self, session, *args, **kwargs):
        self.sas = session
        # logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.WARN)
        self.sas = session
        logging.debug("Initialization of SAS Macro: " + self.sas.saslog())

    @staticmethod
    def _errorLog(log):
        if isinstance(log, str):
            lines = re.split(r'[\n]\s*', log)
            i = 0
            elog = []
            for line in lines:
                i += 1
                e = []
                if line.startswith('ERROR'):
                    e = lines[(max(i - 1, 0)):(min(i + 0, len(lines)))]
                elog = elog + e
            return "\n".join(elog)
        else:
            print("log is not a string but type:%s" % (str(type(log))))

    @staticmethod
    def _genCode(key, **kwargs):
        code = key
        product = kwargs["product"]
        args = kwargs["args"]
        product.logger.debug(key + " statement,length: %s,%s", args[key], len(args[key]))

        if isinstance(args[key], list):
            code += " " + " ".join(args[key])
        elif isinstance(args[key], bool) and not args[key]:
            return ""  # We _don't_ want it here.
        else:
            code += " %s" % (args[key])

        code += ";\n"
        return code

    @staticmethod
    def _genCodeSingleVar(key, **kwargs):
        args = kwargs["args"]
        if len(args[key]) != 1:
            raise ValueError("ERROR in code submission. " + key.upper() + " can only have one variable and you submitted: %s",
                             args[key])

        return SASProcCommons._genCode(key, **kwargs)

    @staticmethod
    def _getKeywords():
        """
        Contains a list of keywords for a SAS Proc statement. If the keyword requires
        special code generation handling, it is represented by a tuple of the key, and
        the function that generates the given keyword's code.
        :return: A list of keywords, where the
        """
        return [
            "absorb",
            "add",
            ("architecture", _SpecialKeywords._architecture_key),
            "assess",
            "autoreg",
            "bayes",
            "blockseason",
            "by",
            "cdfplot",
            ("cls", lambda key, **kwargs: SASProcCommons._genCode("class", **kwargs)),
            "code",
            "comphist",
            "corr",
            "crosscorr",
            "crossvar",
            "cycle",
            "decomp",
            "deplag",
            "effect",
            "fcmport",
            ("freq", SASProcCommons._genCodeSingleVar),
            "forecast",
            "hidden",
            "id",
            "histogram",
            "hazardratio",
            "identify",
            ("impute", _SpecialKeywords._impute_key),
            ("input",_SpecialKeywords._input_key),
            "inset",
            "intervals",
            "irregular",
            "level",
            "model",
            "contrast",
            "estimate",
            "lsmeans",
            "lsmestimate",
            "test",
            "manova",
            "means",
            "nloptions",
            "oddsratio",
            "outarrays",
            "outscalars",
            "outlier",
            "paired",
            "parms",
            "partial",
            "pathdiagram",
            "performance",
            "ppplot",
            "prior",
            ("priors", _SpecialKeywords._priors_key),
            "probplot",
            "qqplot",
            "random",
            "randomreg",
            "repeated",
            "roc",
            "season",
            ("selection",_SpecialKeywords._selection_key),
            "slope",
            "splinereg",
            "splineseason",
            "store",
            "trend",
            "slice",
            "spec",
            "strata",
            ("target", _SpecialKeywords._target_key),
            ("train", _SpecialKeywords._train_key),
            "var",
            ("weight", SASProcCommons._genCodeSingleVar),
            "grow",
            "prune",
            "rules",
            "partition",
            ("out", _SpecialKeywords._out_key),
            "xchart",
            ("score", _SpecialKeywords._score_key),
            ("save", _SpecialKeywords._save_key)
        ]

    @staticmethod
    def _makeProcCallMacro(product, objtype: str, objname: str, data: object = None, args: dict = None) -> str:
        """
        This method generates the SAS code from the python objects and included data and arguments.
        The list of args in this method is largely alphabetical but there are exceptions in order to
        satisfy the order needs of the statements for the procedure. as an example...
        http://support.sas.com/documentation/cdl/en/statug/68162/HTML/default/viewer.htm#statug_glm_syntax.htm#statug.glm.glmpostable

        :param objtype: str -- proc name
        :param objname: str -- 3 digit code for proc
        :param data: sas dataset object
        :param args: dict --  proc arguments
        :return: str -- the SAS code needed to execute on the server
        """
        plot = ''
        outmeth = ''
        procopts = ''
        # Set ODS graphic generation to True by default
        ODSGraphics = args.get('ODSGraphics', True)

        # The different SAS products vary slightly in plotting and out methods.
        # this block sets the options correctly for plotting and output statements
        if product.sasproduct.lower() == 'stat' and not ('ODSGraphics' in args.keys() or ODSGraphics == False) :
            outmeth = ''
            plot = 'plot=all'
        elif product.sasproduct.lower() == 'qc':
            outmeth = ''
            plot = ''
        elif product.sasproduct.lower() == 'ets' and not ('ODSGraphics' in args.keys() or ODSGraphics == False) :
            outmeth = 'out'
            plot = 'plot=all'
        elif product.sasproduct.lower() == 'em':
            outmeth = ''
            plot = ''
        elif product.sasproduct.lower() == 'dmml':
            outmeth = 'out'
            plot = ''
        product.logger.debug("product caller: " + product.sasproduct.lower())
        code = "%macro proccall(d);\n"
        # resolve issues withe Proc options, out= and plots=
        # The procopts statement should be in every procedure as a way to pass arbitrary options to the procedures
        if 'procopts' in args:
            product.logger.debug("procopts statement,length: %s,%s", args['procopts'], len(args['procopts']))
            procopts = args['procopts']
        if 'outmeth' in args:
            outmeth = args['outmeth']
        if 'plot' in args:
            plot = args['plot']
        if len(outmeth) and 'out' in args:
            outds = args['out']
            outstr = outds.libref + '.' + outds.table
            code += "proc %s data=%s.%s%s %s %s=%s %s ;\n" % (
                objtype, data.libref, data.table, data._dsopts(), plot, outmeth, outstr, procopts)
        else:
            code += "proc %s data=%s.%s%s %s %s ;\n" % (objtype, data.libref, data.table, data._dsopts(), plot, procopts)
        product.logger.debug("args value: " + str(args))
        product.logger.debug("args type: " + str(type(args)))

        # this list is largely alphabetical but there are exceptions in order to
        # satisfy the order needs of the statements for the procedure
        # as an example... http://support.sas.com/documentation/cdl/en/statug/68162/HTML/default/viewer.htm#statug_glm_syntax.htm#statug.glm.glmpostable

        keywords = (key for key in SASProcCommons._getKeywords() if key in args
                            or (isinstance(key, tuple) and key[0] in args))

        # change keys to strings explicitly
        vars = {"product": product, "objname":objname, "objtype":objtype, "args":args, "data":data}
        for keyword in keywords:
            if isinstance(keyword, tuple):
                # We have something that requires special handling
                code += keyword[1](keyword[0], **vars)
            else:
                code += SASProcCommons._genCode(keyword, **vars)



        # passthrough facility for procedures with special circumstances
        if 'stmtpassthrough' in args:
            code += str(args['stmtpassthrough'])

        code += "run; quit; %mend;\n"
        code += "%%mangobj(%s,%s,%s);" % (objname, objtype, data.table)
        product.logger.debug("Proc code submission: " + str(code))
        return code

    def _objectmethods(self, obj: str, *args) -> list:
        """
        This method parses the SAS log for artifacts (tables and graphics) that were created
        from the procedure method call

        :param obj: str -- proc object
        :param args: list likely none
        :return: list -- the tables and graphs available for tab complete
        """
        code = "%listdata("
        code += obj
        code += ");"
        self.logger.debug("Object Method macro call: " + str(code))
        res = self.sas.submit(code, "text")
        meth = res['LOG'].splitlines()
        for i in range(len(meth)):
            meth[i] = meth[i].lstrip().rstrip()
        self.logger.debug('SAS Log: ' + res['LOG'])
        objlist = meth[meth.index('startparse9878') + 1:meth.index('endparse9878')]
        self.logger.debug("PROC attr list: " + str(objlist))
        return objlist


    @staticmethod
    def _charlist(product, data) -> list:
        """
        Private method to return the variables in a SAS Data set that are of type char

        :param data: SAS Data object to process
        :return: list of character variables
        :rtype: list
        """
        # Get list of character variables to add to nominal list
        char_string = """
        data _null_; file LOG;
          d = open('{0}.{1}');
          nvars = attrn(d, 'NVARS');
          put 'VARLIST=';
          do i = 1 to nvars;
             vart = vartype(d, i);
             var  = varname(d, i);
             if vart eq 'C' then
                put var; end;
          put 'VARLISTend=';
        run;
        """
        # ignore teach_me_SAS mode to run contents
        nosub = product.sas.nosub
        product.sas.nosub = False
        ll = product.sas.submit(char_string.format(data.libref, data.table + data._dsopts()))
        product.sas.nosub = nosub
        l2 = ll['LOG'].partition("VARLIST=\n")
        l2 = l2[2].rpartition("VARLISTend=\n")
        charlist1 = l2[0].split("\n")
        del charlist1[len(charlist1) - 1]
        charlist1 = [x.casefold() for x in charlist1]
        return charlist1

    @staticmethod
    def _processNominals(product, kwargs, data):
        nom = kwargs.pop('nominals', None)
        inputs = kwargs.pop('input', None)
        tgt = kwargs.pop('target', None)
        targOpts = kwargs.pop('targOpts', None)

        # get char variables and nominals list if it exists
        if nom is None:
            dsnom = SASProcCommons._charlist(product, data)
        elif isinstance(nom, list):
            nom = [x.casefold() for x in nom]
            dsnom = list(set(SASProcCommons._charlist(product, data)) | set(nom))
        else:
            raise SyntaxWarning('nominals must be list type. You gave %s.' % str(type(nom)))
        if tgt is not None:
            # what object type is target
            if isinstance(tgt, str):
                # if there is special character do nothing
                if len([word for word in tgt if any(letter in word for letter in '/\:;.%')]) != 0:
                    kwargs['target'] = tgt
                else:
                    # turn str into list and search for nominals
                    tgt_list = tgt.casefold().split()
                    nom_target = list(set(tgt_list).intersection(dsnom))
                    int_target = list(set(tgt_list).difference(dsnom))
                    if (nom_target is not None and len(nom_target) > 0) and (
                            int_target is not None and len(int_target) > 0):
                        kwargs['target'] = {'nominal' : nom_target,
                                            'interval': int_target}
                    elif nom_target is not None and len(nom_target) > 0:
                        kwargs['target'] = {'nominal': nom_target}
                    elif int_target is not None and len(int_target) > 0:
                        kwargs['target'] = {'interval': int_target}
            elif isinstance(tgt, list):
                tgt_list = tgt
                tgt_list = [x.casefold() for x in tgt_list]
                nom_target = list(set(tgt_list).intersection(dsnom))
                int_target = list(set(tgt_list).difference(dsnom))
                if (nom_target is not None and len(nom_target) > 0) and (
                        int_target is not None and len(int_target) > 0):
                    kwargs['target'] = {'nominal' : nom_target,
                                        'interval': int_target}
                elif nom_target is not None and len(nom_target) > 0:
                    kwargs['target'] = {'nominal': nom_target}
                elif int_target is not None and len(int_target) > 0:
                    kwargs['target'] = {'interval': int_target}
            elif isinstance(tgt, dict):
                # are the keys valid
                # TODO: make comparison case insensitive casefold()
                if any(key in tgt.keys() for key in ['nominal', 'interval']):
                    kwargs['target'] = tgt
            else:
                raise SyntaxError("Target must be a string, list, or dictionary you provided: %s" % str(type(tgt)))
        if targOpts is not None:
            kwargs['target']['targOpts'] = targOpts
        if inputs is not None:
            # what object type is input
            if isinstance(inputs, str):
                # if there is only one word or special character do nothing
                if len(inputs.split()) == 1 or len(
                        [word for word in inputs if any(letter in word for letter in '-/\\:;.%')]) != 0:
                    kwargs['input'] = inputs
                else:
                    # turn str into list and search for nominals
                    inputs_list = inputs.casefold().split()
                    nom_input = list(set(inputs_list).intersection(dsnom))
                    int_input = list(set(inputs_list).difference(dsnom))
                    if (nom_input is not None and len(nom_input) > 0) and (
                            int_input is not None and len(int_input) > 0):
                        kwargs['input'] = {'nominal' : nom_input,
                                           'interval': int_input}
                    elif nom_input is not None and len(nom_input) > 0:
                        kwargs['input'] = {'nominal': nom_input}
                    elif int_input is not None and len(int_input) > 0:
                        kwargs['input'] = {'interval': int_input}
            elif isinstance(inputs, list):
                inputs_list = inputs
                inputs_list = [x.casefold() for x in inputs_list]
                nom_input = list(set(inputs_list).intersection(dsnom))
                int_input = list(set(inputs_list).difference(dsnom))
                if (nom_input is not None and len(nom_input) > 0) and (int_input is not None and len(int_input) > 0):
                    kwargs['input'] = {'nominal' : nom_input,
                                       'interval': int_input}
                elif nom_input is not None and len(nom_input) > 0:
                    kwargs['input'] = {'nominal': nom_input}
                elif int_input is not None and len(int_input) > 0:
                    kwargs['input'] = {'interval': int_input}
            elif isinstance(inputs, dict):
                # are the keys valid
                # TODO: make comparison case insensitive casefold()
                if any(key in inputs.keys() for key in ['nominal', 'interval']):
                    kwargs['input'] = inputs
            else:
                raise SyntaxError("input must be a string, list, or dictionary you provided: %s" % str(type(inputs)))
        return kwargs

    @staticmethod
    def _target_stmt(stmt: object) -> tuple:
        """
        takes the target key from kwargs and processes it to aid in the generation of a model statement
        :param stmt: str, list, or dict that contains the model information.
        :return: tuple of strings one for the class statement one for the model statements
        """
        # make sure target is a single variable extra split to account for level= option
        code = ''
        cls  = ''
        if isinstance(stmt, str):
            if len(stmt.split('/')[0].split()) == 1:
                code += "%s" % (stmt)
            else:
                raise SyntaxError(
                    "ERROR in code submission. TARGET can only have one variable and you submitted: %s" % stmt)
        elif isinstance(stmt, list):
            if len(stmt) == 1:
                code += "%s" % str(stmt[0])
            else:
                raise SyntaxError("The target list must have exactly one member")
        elif isinstance(stmt, dict):
            try:
                # check there there is only one target:
                length = 0
                try:
                    length += len([stmt['nominal'], stmt['interval']])
                except KeyError:
                    try:
                        length += len([stmt['nominal']])
                    except KeyError:
                        try:
                            length += len([stmt['interval']])
                        except KeyError:
                            raise
                if length  == 1:
                    if 'interval' in stmt.keys():
                        if isinstance(stmt['interval'], str):
                            code += "%s" % stmt['interval']
                        if isinstance(stmt['interval'], list):
                            code += "%s" % " ".join(stmt['interval'])
                    if 'nominal' in stmt.keys():
                        if isinstance(stmt['nominal'], str):
                            code += "%s" % stmt['nominal']
                            cls  += "%s" % stmt['nominal']

                        if isinstance(stmt['nominal'], list):
                            code += "%s" % " ".join(stmt['nominal'])
                            cls  += "%s" % " ".join(stmt['nominal'])
                else:
                    raise SyntaxError
            except SyntaxError:
                print("SyntaxError: TARGET can only have one variable")
            except KeyError:
                print("KeyError: Proper keys not found for TARGET dictionary: %s" % stmt.keys())
        else:
            raise SyntaxError("TARGET is in an unknown format: %s" % str(stmt))
        return (code, cls)

    @staticmethod
    def _input_stmt(stmt: object) -> tuple:
        """
        takes the input key from kwargs and processes it to aid in the generation of a model statement
        :param stmt: str, list, or dict that contains the model information.
        :return: tuple of strings one for the class statement one for the model statements
        """
        code = ''
        cls  = ''
        if isinstance(stmt, str):
            code += "%s " % (stmt)
        elif isinstance(stmt, dict):
            try:
                if 'interval' in stmt.keys():
                    if isinstance(stmt['interval'], str):
                        code += "%s " % stmt['interval']
                    if isinstance(stmt['interval'], list):
                        code += "%s " % " ".join(stmt['interval'])
                if 'nominal' in stmt.keys():
                    if isinstance(stmt['nominal'], str):
                        code += "%s " % stmt['nominal']
                        cls += "%s " % stmt['nominal']
                    if isinstance(stmt['nominal'], list):
                        code += "%s " % " ".join(stmt['nominal'])
                        cls += "%s " % " ".join(stmt['nominal'])
            except:
                raise SyntaxError("Proper Keys not found for INPUT dictionary: %s" % stmt.keys())
        elif isinstance(stmt, list):
            if len(stmt) == 1:
                code += "%s" % str(stmt[0])
            elif len(stmt) > 1:
                code += "%s" % " ".join(stmt)
            else:
                raise SyntaxError("The input list has no members")
        else:
            raise SyntaxError("INPUT is in an unknown format: %s" % str(stmt))
        return (code, cls)

    @staticmethod
    def _run_proc(product, procname: str, required_set: set, legal_set: set, **kwargs: dict):
        """
        This internal method takes the options and statements from the PROC and generates
        the code needed to submit it to SAS. It then submits the code.
        :param product:
        :param procname: str
        :param required_set: set of options
        :param legal_set: set of valid options
        :param kwargs: dict (optional)
        :return: sas result object
        """
        data = kwargs.pop('data', None)
        objtype = procname.lower()
        if 'model' not in kwargs.keys():
            kwargs = SASProcCommons._processNominals(product, kwargs, data)
            if 'model' in required_set:
                tcls_str = ''
                icls_str = ''
                t_str, tcls_str = SASProcCommons._target_stmt(kwargs['target'])
                i_str, icls_str = SASProcCommons._input_stmt(kwargs['input'])

                kwargs['model'] = str(t_str + ' = ' + i_str )
                kwargs['cls'] = str(tcls_str + " " + icls_str)
        verifiedKwargs = SASProcCommons._stmt_check(product, required_set, legal_set, kwargs)
        obj1 = []
        nosub = False
        objname = ''
        log = ''
        if len(verifiedKwargs):
            objname = procname[:3].lower() + product.sas._objcnt()  # translate to a libname so needs to be less than 8
            code = SASProcCommons._makeProcCallMacro(product, objtype, objname, data, verifiedKwargs)
            product.logger.debug(procname + " macro submission: " + str(code))
            if not product.sas.nosub:
                ll = product.sas.submit(code, "text")
                log = ll['LOG']
                error = SASProcCommons._errorLog(log)
                isinstance(error, str)
                if len(error) > 1:
                    RuntimeWarning("ERRORS found in SAS log: \n%s" % error)
                    return SASresults(obj1, product.sas, objname, nosub, log)
                try:
                    obj1 = SASProcCommons._objectmethods(product, objname)
                    product.logger.debug(obj1)
                except Exception:
                    pass
            else:
                print(code)
                nosub = True
        else:
            RuntimeWarning("Error in code submission")
        return SASresults(obj1, product.sas, objname, nosub, log)

    @staticmethod
    def _stmt_check(self, req: set, legal: set, stmt: dict) -> dict:
        """
        This method checks to make sure that the proc has all required statements and removes any statements
        aren't valid. Missing required statements is an error. Extra statements are not.
        :param req: set
        :param legal: set
        :param stmt: dict
        :return: dictonary of verified statements
        """
        # debug the argument list
        if self.logger.level == 10:
            for k, v in stmt.items():
                if type(v) is str:
                    print("Key: " + k + ", Value: " + v)
                else:
                    print("Key: " + k + ", Value: " + str(type(v)))

        # required statements
        reqSet = req
        if len(reqSet):
            missing_set = reqSet.difference(set(stmt.keys()))
            if missing_set:
                if not stmt.get('score'): # till we handle either/or required. proc can be called more than one way w/ diff requirements
                   raise SyntaxError("You are missing %d required statements:\n%s" % (len(missing_set), str(missing_set)))

        # legal statements
        legalSet = legal
        if len(legalSet):
            if len(reqSet):
                totSet = legalSet | reqSet
            else:
                totSet = legalSet
            generalSet = set(['ODSGraphics', 'stmtpassthrough', 'targOpts', 'procopts'])
            extraSet = set(stmt.keys() - generalSet).difference(totSet)  # find keys not in legal or required sets
            if extraSet:
                for item in extraSet:
                    stmt.pop(item, None)
                SyntaxWarning("The following %d statements are invalid and will be ignored:\nextraSet " % len(extraSet))
        return stmt


class _SpecialKeywords:
    @staticmethod
    def _architecture_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        product.logger.debug("architecture statement,length: %s,%s", args['architecture'], len(args['architecture']))
        if args['architecture'].lower().strip() in ['logistic', 'mlp', 'mlp direct']:
            return "architecture %s;\n" % (args['architecture'])
        else:
            raise ValueError("Architecture may only have values ['logistic', 'mlp', 'mlp direct'], recieved '%s' instead.")

    @staticmethod
    def _impute_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        code = ""
        product.logger.debug("impute statement,length: %s,%s", args['impute'], len(args['impute']))
        if not (isinstance(args['impute'], dict) or isinstance(args['impute'], str)):
            raise SyntaxError("IMPUTE must be a dictionary: %s" % str(type(args['impute'])))
        if isinstance(args['impute'], dict):
            usedVars = []
            tup_code = ''
            contantValues = args['impute'].pop('value', None)
            if contantValues is not None:
                if not all(isinstance(x, tuple) for x in contantValues):
                    raise SyntaxError("The elements in the 'value' key must be tuples")
                for t in contantValues:
                    tup_code += "impute %s / value = %s;\n" % (t[0], t[1])
                    usedVars.append(t[0])
            meth_code = ''
            for key, values in args['impute'].items():
                for v in values:
                    meth_code += 'impute %s / method = %s;\n' % (v, key)
                    usedVars.append(v)
            code += '\ninput ' + ' '.join(list(set(usedVars))) + ';\n' + tup_code + meth_code + 'run;'
        elif isinstance(args['impute'], str):
            code += "impute %s;\n" % (args['impute'])

        return code
    
    @staticmethod
    def _input_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        code = ""
        if isinstance(args['input'], str):
            product.logger.debug("input statement,length: %s,%s", kwargs["args"]['input'], len(kwargs["args"]['input']))
            code += "input %s;\n" % (kwargs["args"]['input'])
        elif isinstance(kwargs["args"]['input'], dict):
            try:
                # fix var type names for HPNEURAL
                nomstr = 'nominal'
                intstr = 'interval'
                if kwargs["objtype"].casefold() =='hpneural':
                    nomstr = 'nom'
                    intstr = 'int'
                if 'interval' in args['input'].keys():
                    if isinstance(args['input']['interval'], str):
                        code += "input %s /level=%s;\n" % (kwargs["args"]['input']['interval'], intstr)
                    if isinstance(args['input']['interval'], list):
                        code += "input %s /level=%s;\n" % (" ".join(kwargs["args"]['input']['interval']), intstr )
                if 'nominal' in kwargs["args"]['input'].keys():
                    if isinstance(kwargs["args"]['input']['nominal'], str):
                        code += "input %s /level=%s;\n" % (kwargs["args"]['input']['nominal'], nomstr)
                    if isinstance(kwargs["args"]['input']['nominal'], list):
                        code += "input %s /level=%s;\n" % (" ".join(kwargs["args"]['input']['nominal']), nomstr)
            except:
                raise SyntaxError("Proper Keys not found for INPUT dictionary: %s" % kwargs["args"]['input'].keys())
        elif isinstance(kwargs["args"]['input'], list):
            if len(kwargs["args"]['input']) == 1:
                code += "input %s;\n" % str(kwargs["args"]['input'][0])
            elif len(kwargs["args"]['input']) > 1:
                code += "input %s;\n" % " ".join(kwargs["args"]['input'])
            else:
                raise SyntaxError("The input list has no members")
        else:
            raise SyntaxError("INPUT is in an unknown format: %s" % str(kwargs["args"]['input']))
        return code

    @staticmethod
    def _priors_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        code = ""
        if isinstance(args['priors'], str):
            product.logger.debug("priors statement,length: %s,%s", args['priors'], len(args['priors']))
            code += "priors %s;\n" % (args['priors'])
        elif isinstance(args['priors'], list):
            if len(args['priors']) == 1:
                code += "priors %s;\n" % str(args['priors'][0])
            elif len(args['priors']) > 1:
                code += "priors %s;\n" % " ".join(args['priors'])
            else:
                raise SyntaxError("The priors list has no members")
        else:
            raise SyntaxError("priors is in an unknown format: %s" % str(args['priors']))
        return code

    @staticmethod
    def _selection_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        code = ""
        if isinstance(args['selection'], str):
            if args['selection'].lower().strip() in ['none', 'forward', 'backward', 'stepwise', 'forwardswap',
                                                     'lar', 'lasso']:
                product.logger.debug("selection statement,length: %s,%s", args['selection'], len(args['selection']))
                code += "selection method=%s;\n" % (args['selection'])
        elif isinstance(args['selection'], dict):
            if bool(args['selection']): # is the dictionary empty
                m = args['selection'].pop('method', '')
                me = args['selection'].pop('maxeffects', None)
                if me is not None:
                    if int(me) > 0 and m != 'backward':
                        args['selection']['maxeffects'] = me
                d = args['selection'].pop('details', '')
                dstr = ''
                if len(d) > 0:
                    dstr = 'details = %s' % d
                code += "selection method=%s (%s)  %s;" % (m, ' '.join('{}={}'.format(key, val) for key, val in args['selection'].items()), dstr)
        return code


    @staticmethod
    def _target_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        objtype = kwargs["objtype"]
        code = ""

        product.logger.debug("target statement,length: %s,%s", args['target'], len(args['target']))
        # make sure target is a single variable extra split to account for level= option
        if isinstance(args['target'], str):
            if len(args['target'].split('/')[0].split()) == 1:
                code += "target %s;\n" % (args['target'])
            else:
                raise SyntaxError(
                    "ERROR in code submission. TARGET can only have one variable and you submitted: %s" % args[
                        'target'])
        elif isinstance(args['target'], list):
            if len(args['target']) == 1:
                code += "target %s;\n" % str(args['input'][0])
            else:
                raise SyntaxError("The target list must have exactly one member")
        elif isinstance(args['target'], dict):
            try:
                # check there there is only one target:
                length=0
                try:
                    length += len([args['target']['nominal'], args['target']['interval'] ])
                except KeyError:
                    try:
                        length += len([args['target']['nominal']])
                    except KeyError:
                        try:
                            length += len([args['target']['interval']])
                        except KeyError:
                            raise
                if length  == 1:
                    # fix var type names for HPNEURAL
                    nomstr = 'nominal'
                    intstr = 'interval'
                    targOpts = ''
                    try:
                        targOpts = ' '.join('{}={}'.format(key, val) for key, val in args['target']['targOpts'].items())
                    except:
                        pass
                    if objtype.casefold() == 'hpneural':
                        nomstr = 'nom'
                        intstr = 'int'
                    if 'interval' in args['target'].keys():
                        if isinstance(args['target']['interval'], str):
                            code += "target %s /level=%s %s;\n" % (args['target']['interval'], intstr, targOpts)
                        if isinstance(args['target']['interval'], list):
                            code += "target %s /level=%s %s;\n" % (" ".join(args['target']['interval']), intstr, targOpts)
                    if 'nominal' in args['target'].keys():
                        if isinstance(args['target']['nominal'], str):
                            code += "target %s /level=%s;\n" % (args['target']['nominal'], nomstr)
                        if isinstance(args['target']['nominal'], list):
                            code += "target %s /level=%s;\n" % (" ".join(args['target']['nominal']), nomstr)
                else:
                    raise SyntaxError
            except SyntaxError:
                print("SyntaxError: TARGET can only have one variable")
            except KeyError:
                print("KeyError: Proper keys not found for TARGET dictionary: %s" % args['target'].keys())
        else:
            raise SyntaxError("TARGET is in an unknown format: %s" % str(args['target']))
        return code


    @staticmethod
    def _train_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        code = ""

        if isinstance(args['train'], dict):
            try:
                if all (k in args['train'] for k in ("numtries", "maxiter")):
                    code += "train numtries=%s maxiter=%s;\n" % (args['train']["numtries"], args['train']["maxiter"])
            except:
                raise SyntaxError("Proper Keys not found for TRAIN dictionary: %s" % args['train'].keys())
        else:
            product.logger.debug("train statement,length: %s,%s", args['train'], len(args['train']))
            code += "train %s;\n" % (args['train'])
        return code


    @staticmethod
    def _out_key(key, **kwargs):
        args = kwargs["args"]
        objtype = kwargs["objtype"]
        code = ""

        if not isinstance(args['out'], dict):
            outds = args['out']
            outstr = outds.libref + '.' + outds.table
            code += "output out=%s;\n" % outstr
        else:
            t = args['out'].pop("table", None)
            l = args['out'].pop("libref", None)
            d = args['out'].pop("data", None)
            if t and l:
                outstr = l + '.' + t
            elif d:
                outstr = d.libref + '.' + d.table
            else:
                raise SyntaxError("OUT statement is not in a recognized form either {'libname':'foo', 'table':'bar'} or {'data':'sasdataobject'}  %s" % str(objtype))

            varlist = ' '.join('{}={}'.format(key, val) for key, val in args['out'].items())
            code += "output out=%s %s;\n" % (outstr, varlist)

        return code

    @staticmethod
    def _score_key(key, **kwargs):
        args = kwargs["args"]
        objtype = kwargs["objtype"]
        data = kwargs["data"]
        code = ""

        if isinstance(args['score'], str):
            code += "score %s;\n" % args['score']
        else:
            scoreds = args['score']
            if objtype.upper() == "HP4SCORE":
                f = scoreds.get('file')
                d = scoreds.get('out')
                o = d.libref+'.'+d.table
                code += "score file='"+f+"' out="+o+";\n"
            elif objtype.upper() == 'TPSPLINE':
                code += "score data=%s.%s out=%s.%s;\n" % (data.libref, data.table, scoreds.libref, scoreds.table)
            else:
                code += "score out=%s.%s;\n" % (scoreds.libref, scoreds.table)

        return code

    @staticmethod
    def _save_key(key, **kwargs):
        args = kwargs["args"]
        product = kwargs["product"]
        objtype = kwargs["objtype"]
        objname = kwargs["objname"]
        code = ""

        product.logger.debug("save statement,length: %s,%s", args['save'], len(args['save']))
        if objtype=="hpforest":
            code += "save file='%s';\n" % (args['save'])
        elif objtype=="treeboost":
            if isinstance(args['save'], bool):
                libref=objname
                code += "save fit=%s.%s importance=%s.%s model=%s.%s nodestats=%s.%s rules=%s.%s;\n" % \
                        (libref, "fit", libref, "importance", libref, "model",
                         libref, "nodestats", libref, "rules" )
            elif isinstance(args['save'], dict):
                code += "save %s ;" % ' '.join('{}={}'.format(key, val) for key, val in args['save'].items())
            else:
                raise SyntaxError("SAVE statement object type is not recognized, must be a bool or dict. You provided: %s" % str(type(args["save"])))
        else:
            raise SyntaxError("SAVE statement is not recognized for this procedure: %s" % str(objtype))
        return code
