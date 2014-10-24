'''Test creating a XACML Policy

Adapted from DeveloperWorks Article:

http://www.ibm.com/developerworks/xml/library/x-xacml/

P J Kershaw 18/03/09
'''
from ndg.security.common.authz.xacml import AttributeDesignator, TargetMatch, \
    Target, MatchFunction, EqualFunction


def createPolicyTarget():
    # OpenID designator - string equal match
    subjectDesignatorType = "http://www.w3.org/2001/XMLSchema#anyURI"
    subjectDesignatorId = "urn:oasis:names:tc:xacml:1.0:subject:subject-id"
    subjectMatchId = "urn:oasis:names:tc:xacml:1.0:function:string-equal";
    
    subjectDesignator = AttributeDesignator(AttributeDesignator.SUBJECT_TARGET,
                                            subjectDesignatorType,
                                            subjectDesignatorId)
  
    subjectFunction = EqualFunction(subjectMatchId)
    subjectValue = 'http://localhost:7443/openid/john.smith'
    
    subjectMatch = TargetMatch(TargetMatch.SUBJECT,
                               subjectFunction,
                               subjectDesignator,
                               subjectValue)
    subject = [subjectMatch]
    
    # Regex match to URI
    resourceDesignatorType = "http://www.w3.org/2001/XMLSchema#anyURI"
    resourceDesignatorId ="urn:oasis:names:tc:xacml:1.0:resource:resource-id"

    resourceMatchId="urn:oasis:names:tc:xacml:1.0:function:regexp-string-match"

    resourceDesignator=AttributeDesignator(AttributeDesignator.RESOURCE_TARGET,
                                           resourceDesignatorType,
                                           resourceDesignatorId)

    resourceFunction = MatchFunction(resourceMatchId);
    resourceValue = "http://localhost:7080/secured/.*"

    resourceMatch = TargetMatch(TargetMatch.RESOURCE,
                                resourceFunction,
                                resourceDesignator,
                                resourceValue)
    resource = [resourceMatch]

    subjects = [subject]
    resources = [resource]

    # No action type attributes have been specified in the target
    return Target(subjects, resources)

def createRuleCondition():
    conditionArgs = []

    # Define the name and type of the attribute to be used in the condition
    designatorType = "http://www.w3.org/2001/XMLSchema#string"
    designatorId = "group"

    # Pick the function that the condition uses
    conditionFunction = EqualFunction(
              "urn:oasis:names:tc:xacml:1.0:function:string-equal")

    # Choose the function to pick one of the multiple values returned by 
    # AttributeDesignator
    applyFunction = EqualFunction(
              "urn:oasis:names:tc:xacml:1.0:function:" + "string-one-and-only")

    # Create the AttributeDesignator
    designator = AttributeDesignator(AttributeDesignator.SUBJECT_TARGET,
                                     designatorType,
                                     designatorId,
                                     False,
                                     None)
    applyArgs = [designator]

    # Create the Apply object and pass it the function and the 
    # AttributeDesignator. The function picks up one of the multiple values 
    # returned by the AttributeDesignator
    apply = Apply(applyFunction, applyArgs, false)

    # Add the new apply element to the list of inputs
    # to the condition along with the AttributeValue
    conditionArgs.add(apply)

    value = StringAttribute("owner")
    conditionArgs.add(value)

    # Finally, create and return the condition
    condition = Apply(conditionFunction, conditionArgs, true)
    return condition


def createRuleTarget():
    return ruleTarget

def createRules():
    
    # Step 1: Define the identifier for the rule
    ruleId = URI("ProjectPlanAccessRule")
    ruleDescription = "Rule for accessing project plan"

    # Step 2: Define the effect of the rule
    effect = Result.DECISION_PERMIT

    # Step 3: Get the target for the rule
    target = createRuleTarget()

    # Step 4: Get the condition for the rule
    condition = createRuleCondition()

    # Step 5: Create the rule
    openRule = Rule(ruleId, effect, ruleDescription, target, condition)

    # Create a list for the rules and add the rule to it
    ruleList = [openRule]

    return ruleList

if __name__ == "__main__":
    target = createPolicyTarget()
