# Output backends for sigmac
# Copyright 


import re
from .base import SingleTextQueryBackend

import json
import re
import sys
import uuid 
import sigma
import yaml
from sigma.parser.modifiers.type import SigmaRegularExpressionModifier
from .base import BaseBackend, SingleTextQueryBackend
from .mixins import RulenameCommentMixin, MultiRuleOutputMixin, QuoteCharMixin
from .exceptions import NotSupportedError
from sigma.parser.condition import ConditionNOT, ConditionOR, ConditionAND, NodeSubexpression
from datetime import datetime

class FindelisBackend(BaseBackend,QuoteCharMixin):
    """"""  
    identifier = "fidelis"
    active = True
    default_config = ["fidelis", "sysmon"]
    reEscape = re.compile('(\\\\)')
    _isdebug = False

    #try to fix this with regex and stuff 
    #reClear = re.compile('[*]')

    _operators = {
        "equal":"=",
        "contains":"=~",
        "starts_with":"*=",
        "ends_with":"=*",    
        "regex":"~",
        "is_in_list":"IN",
        "is_empty":"[]"      
    }
    _operators_neg = {
        "equal":"!=",
        "contains":"!~",
        "starts_with":"!*=",
        "ends_with":"!=*",
        "regex":"~",
        "is_empty":"![]"
    }
    # Start with positive operators and switch negative if NOT statement
    _operator_set = _operators
    _direction = "positive"
    
    # for debuging
    boolean_path = ""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queries = []  
       
     
    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        self.title = sigmaparser.parsedyaml["title"]
        self.description = sigmaparser.parsedyaml["description"]
       
        #print([x.split("|")[0] for x in sigmaparser.values.keys()])

        logsource = sigmaparser.get_logsource()
        if logsource is None:
            self.indices = None
        else:
            self.indices = logsource.index
            if len(self.indices) == 0:
                self.indices = None

        try:
            self.interval = sigmaparser.parsedyaml['detection']['timeframe']
        except:
            pass
        
        if (self._isdebug):
            print("------------------------START OF DEBUGGING---------------------------")
        
        for parsed in sigmaparser.condparsed:
            self.generateBefore(parsed)
            self.generateQuery(parsed)
            self.generateAfter(parsed)
        
    

    def generateQuery(self, parsed):
        self.queries[-1]['criteriaV3']['filter'] = self.generateNode(parsed.parsedSearch)
        if parsed.parsedAgg:
            self.generateAggregation(parsed.parsedAgg)
    

    def generateBefore(self, parsed):
        self.queries.append({'criteriaV3':{'entityType':'process','filter':{},"relationshipFilter":None},"endpointCriteria":None})


    def getOperator(self,value):
        if isinstance(value, str) and value.startswith("*") and value.endswith("*") and value.count('*')==2:
            return self._operator_set["contains"]
        elif isinstance(value, str) and value.startswith("*") and value.count('*')==1:
            return self._operator_set["ends_with"]
        elif isinstance(value, str) and value.endswith("*") and value.count('*')==1:
            return self._operator_set["starts_with"]
        elif isinstance(value, str) and value.count('*')>=2:
            return self._operator_set["regex"]
        else:
            return self._operator_set["equal"]
    
    def debug(self,node):
        if (self._isdebug):
            print("")
            print(" --- Node details: \n"+str(node))
            
            if(type(node) in {ConditionNOT, ConditionOR, ConditionAND, NodeSubexpression}):
                print("       \---- Node ITEMS type: "+str(type(node.items)))
                for item in node.items:
                    print("             \--------Item type: "+str(type(item)))
            else:
                print("       \---- Node type: "+str(type(node)))
        
    def generateANDNode(self, node):
          

        #debug
        self.debug(node)

         # if NOT condition we change AND to OR
        if (self._direction=="negative"):
            andNode = {'filterType': 'composite', 'logic':'or','filters':[]}  
        else:
            andNode = {'filterType': 'composite', 'logic':'and','filters':[]}  

        generated = [ self.generateNode(val) for val in node ]         
        andNode['filters'] = generated
        

        return andNode
    
    def generateORNode(self, node):
          
        #debug
        self.debug(node)

        # if NOT condition we change OR to AND
        if (self._direction=="negative"):
            orNode = {'filterType':'composite','logic':'and','filters':[]}    
        else:
            orNode = {'filterType':'composite','logic':'or','filters':[]}       
        
        generated = [ self.generateNode(val) for val in node ]         
        orNode['filters'] = generated

           
        return orNode
    
    def generateSubexpressionNode(self, node):
        
        #debug
        self.debug(node)

        return self.generateNode(node.items)
    
    def generateNOTNode(self, node):
        
        #set direction
        self._direction = "negative"
        #debug
        self.debug(node)

        #change operator set to negative operators
        self._operator_set = self._operators_neg    
        generated = self.generateNode(node.item)


        #change operator set back to positive operators
        self._operator_set = self._operators    
        #set direction back to positive
        self._direction = "positive"

        return  generated
       
        
    #Currently not used since in generateMapItemNode we return the value directly
    def generateValueNode(self, node):
        
        #debug
        self.debug(node)

        return super().generateValueNode(node)
    

    def generateMapItemNode(self, node):
        
        #debug
        self.debug(node)
        key, value = node

        if type(value) is list: # This is for MapItemListNode
            #if only one item           
            if (len(value)==1):
                      return {'filterType':'criteria','column':key,'operator':self.getOperator(value[0]),'value':self.cleanValue(str(value[0])) }
            else:
                # if NOT condition we change OR to AND
                if (self._direction=="negative"):
                    orNode = {'filterType':'composite','logic':'and','filters':[]}    
                else:
                    orNode = {'filterType':'composite','logic':'or','filters':[]}    

                for v in value:
                    orNode['filters'].append({'filterType':'criteria','column':key,'operator':self.getOperator(v),'value':self.cleanValue(str(v)) })                              
                return orNode
        elif value is None:
            return {'filterType':'criteria','column':key,'operator':self.getOperator(value),'value':''}
        elif type(value) in (str, int):        
            return  {'filterType':'criteria','column':key,'operator':self.getOperator(value),'value':self.cleanValue(str(value))}
       
        else:
            raise TypeError("Map values must be strings, numbers, lists, null or regular expression, not " + str(type(value)))

    def cleanValue(self,value):
        operator = self.getOperator(value)
        #if regular expresion we use .* and operator ~
        if (operator == self._operator_set["regex"]):
            value = value.replace("*",".*")
        #if operator starts with, ends with or contains, we remove *
        else:
            value= value.replace("*","")

        return super().cleanValue(value)

    def generateListNode(self, node):
        #debug
        self.debug(node)
        return super().generateListNode(node)
      
    def generateMapItemListNode(self, fieldname, value):
        #debug
        self.debug(node)
        return super().generateMapItemListNode(fieldname,value)

    def generateMapItemTypedNode(self, fieldname, value):
        #debug
        self.debug(node)
        return super().generateMapItemTypedNode(fieldname,value)


    def generateTypedValueNode(self, node):
        return super().generateTypedValueNode(node)

    def generateNULLValueNode(self, node):
        return super().generateNULLValueNode(node)

    def generateNotNULLValueNode(self, node):
        return super().generateNotNULLValueNode()

    def generateNode(self, node):
        self.boolean_path = self.boolean_path + "  <--->  " + str(type(node))
        return super().generateNode(node)
       


    def finalize(self):
        """
        Is called after the last file was processed with generate(). The right place if this backend is not intended to
        look isolated at each rule, but generates an output which incorporates multiple rules, e.g. dashboards.
        """
        if (self._isdebug):    
            print("-----------------------------BOOLEAN PATH----------------------")
            print(self.boolean_path)
            print("")
            print("-----------------------------END of DEBUGGING----------------------")
            print("")
            print("-----------------------------RAW RULE----------------------")
            print(json.dumps(self.queries[0], indent=2))


        template="""
{
    "AlertRuleId": "__uid__",
    "Name": "__name__",
    "Description": "__description__",
    "CreatedByName": "nil\\\\dgrah",
    "CreatedBy": 1005,
    "SourceInt": 0,
    "CreatedByType": 0,
    "CreatedDate": "__datetime__",
    "RulesJson": "__rule__",
    "EndpointCriteria": null,
    "TargetsAllEndpoints": false,
    "DruidJson": "",
    "IsEnabled": false,
    "ExpirationDate": null,
    "ActionsJson": {
        "scriptJobInfos": [],
        "tags": null,
        "urlCallbacks": [],
        "legacyNetworkIntegrationAlertId": null
    },
    "AlertSeverity": 1,
    "LastHitTime": null,
    "MaxHitsAllowed": null,
    "HitCount": null,
    "DoNotAlert": false,
    "PreInvestigativeDurationMinutes": 1,
    "PostInvestigativeDurationMinutes": 1,
    "TrtBaseline": null,
    "UserModifiedTrt": false,
    "NotifyUpdatedBaseline": false
}
        """
        _uid=uuid.uuid1()
       
      
        rule = json.dumps(self.queries[0], indent=1).replace("\"","\\\"").replace("\n","")
        rule = re.sub(' +', ' ',rule)
        template = template.replace("__rule__",rule).replace("__uid__",str(_uid))
        template = template.replace("__name__","[SIGMA TEST - "+self.title+"]").replace("__description__",self.description)
        template = template.replace("__datetime__",datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f'))

        return template
    
       
        