import pandas as pd
from pathlib import Path
from cyclonedx.model.vulnerability import Vulnerability, VulnerabilityReference, VulnerabilitySource, VulnerabilityScoreSource, VulnerabilityRating, VulnerabilitySeverity, VulnerabilityAdvisory, BomTarget, BomTargetVersionRange, Property, VulnerabilityCredits, VulnerabilityAnalysis
from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.output import make_outputter, BaseOutput
from cyclonedx.model.bom import Bom
from cyclonedx.model import XsUri 
from cyclonedx.model.tool import Tool
from cyclonedx.model.impact_analysis import ImpactAnalysisState, ImpactAnalysisJustification, ImpactAnalysisResponse
from cyclonedx.model.contact import OrganizationalContact, OrganizationalEntity
from cyclonedx.model.component import Component, ComponentType
import json
from datetime import datetime
import csv2vex
import numpy as np
import decimal
from packageurl import PackageURL

default_filename = "vex_config_template.json"
date_format = '%m/%d/%Y'

template = {
    'bom_ref':None,
    'id':None,
    'source':{'url':None, 'name':None},
    'references':[
        {
            'id':None,
            'source':{'url':None, 'name':None}
        }
    ],
    'ratings':[
        {
            'source':{'url':None, 'name':None},
            'score':None,
            'severity':None,
            'method':None,
            'vector':None,
            'justification':None
        }
    ],
    'cwes':None,
    'description':None,
    'detail':None,
    'recommendation':None,
    'workaround':None,
    # 'proofOfConcept':{
    #     'reproductionSteps':None,
    #     'environment':None,
    #     'supportingMaterial':[
    #                             {
    #                                 'content':None
    #                             }
    #                         ],

    # },
    'advisories':[
                    {
                        'title':None, 
                        'url':None
                    }
                ],
    'created':None,
    'published':None,
    'updated':None,
    'rejected':None,
    'credits':{
                'organizations':[
                                    {
                                        'bom-ref':None,
                                        'name':None,
                                        'urls':None,
                                        'contact':[
                                                    {
                                                        'bom-ref':None,
                                                        'name':None,
                                                        'email':None,
                                                        'phone':None  
                                                    }
                                                ]
                                    }
                ], 
                'individuals':[
                                    {
                                        'bom-ref':None,
                                        'name':None,
                                        'email':None,
                                        'phone':None  
                                    }
                            ]
            },
    "tools":[
                {
                    "name":None,
                    "version":None
                }
            ],
    'analysis':{
                    'state':None,
                    'justification':None,
                    'detail':None,
                    'response':[]
                },
    'affects':[
                {
                    'ref':None, 
                    'versions':[]
                }
    ],
    'properties':[]
}

def create_template_file(filename:str|None) -> None:
    file_name = filename if filename is not None else default_filename
    print(f"creating config file {file_name}")
    config_file = Path(file_name)
    config_file.write_text(json.dumps(template, indent=4))

def read_file(data_file:str) -> tuple[int, pd.DataFrame]:
    filepath = Path(data_file)
    ext = filepath.suffix
    data = None
    err = 0
    if not filepath.exists():
        err = -1
    elif ext in ['.csv']:
        data = pd.read_csv(filepath, dtype=str)
        data = data.replace(np.nan, None)
    elif ext in ['.xls', '.xlsx']:
        data = pd.read_excel(filepath, dtype=str)
        data = data.replace(np.nan, None)
    else:
        err = 1
    data = data.apply(lambda x: x.str.strip())
    return err, data

def read_config(json_file:str) -> tuple[int, dict]:
    filepath = Path(json_file)
    ext = filepath.suffix
    data = None
    err = 0
    if not filepath.exists():
        err = -1
    elif ext != '.json':
        err = 1
    else:
        res = filepath.read_text()
        data = json.loads(res)
    return err, data

def get_val(keyword:str, csv_data:pd.Series, config_data:dict) -> str | None:
    res = None
    key = config_data.get(keyword)
    if key is None:
        return res
    if type(key) is str:
        res = csv_data.get(key)
    return res

def normalize_analysis(value:str) -> str:
    if type(value) is not str:
        return None
    normalized_value = value.strip().lower().replace(" ", "_")
    return normalized_value

def get_vulnerability(csv_data:pd.Series, config_data:dict) -> Vulnerability:
    vulnerability = Vulnerability()
    for key in template.keys():
        if hasattr(vulnerability, key) and type(key) is str and key != 'bom_ref': 
            res = get_val(key, csv_data, config_data)
            setattr(vulnerability, key, res)

    #analysis
    if res := config_data.get("analysis"):
        try:
            state_str = get_val('state', csv_data, res)
            state_str = normalize_analysis(state_str)
            state = ImpactAnalysisState(state_str)
        except:
            state = None
        try:
            jus_str = get_val('justification', csv_data, res)
            jus_str = normalize_analysis(jus_str)
            justification = ImpactAnalysisJustification(jus_str)
        except:
            justification = None
        responses = []
        try:
            res_list = res.get('response')
            for i in res_list:
                try:
                    response = normalize_analysis(csv_data.get(i))
                    responses.append(ImpactAnalysisResponse(response))
                except:
                    pass
        except:
            responses = None
        detail = get_val('detail', csv_data, res)
        if state or justification or responses or detail:
            analysis = VulnerabilityAnalysis(state=state, justification=justification, detail=detail, responses=responses)
        else:
            analysis = None
        vulnerability.analysis = analysis

    #source
    if res := config_data.get("source"):
        name = get_val("name", csv_data, res)
        urlstr = get_val("url", csv_data, res)
        if urlstr:
            url = XsUri(urlstr)
        else:
            url = None
        if name or url:
            source = VulnerabilitySource(name=name, url=url)
        else:
            source = None
        vulnerability.source = source
    
    #references
    if ref_config := config_data.get("references"):
        references = [get_reference(csv_data, ref) for ref in ref_config]
        references = [i for i in references if i is not None]
        vulnerability.references = references
    
    #ratings
    if ref_config := config_data.get("ratings"):
        ratings = [get_rating(csv_data, ref) for ref in ref_config]
        ratings = [i for i in ratings if i is not None]
        vulnerability.ratings = ratings

    #advisories
    if ref_config := config_data.get("advisories"):
        advisories = [get_advisory(csv_data, ref) for ref in ref_config]
        advisories = [i for i in advisories if i is not None]
        vulnerability.advisories = advisories
    
    #affects
    if ref_config := config_data.get("affects"):
        affects = [get_affect(csv_data, ref) for ref in ref_config]
        if any(affects):
            affects = [i for j in affects for i in j]
        affects = [i for i in affects if i is not None]
        vulnerability.affects = affects

    #tools
    if ref_config := config_data.get("tools"):
        tools = [get_tool(csv_data, ref) for ref in ref_config]
        tools = [i for i in tools if i is not None]
        vulnerability.tools = tools

    #properties
    if ref_config := config_data.get("properties"):
        properties = [get_property(csv_data, ref) for ref in ref_config]
        properties = [i for i in properties if i is not None]
        vulnerability.properties = properties
    
    #cwes
    if ref_config := get_val("cwes", csv_data, config_data):
        cwes = get_cwes(ref_config)
        cwes = [i for i in cwes if i is not None]
        vulnerability.cwes = cwes
    
    #credits
    if ref_config := config_data.get('credits'):
        credits = get_credits(csv_data, ref_config)
        vulnerability.credits = credits

    #dates
    if vulnerability.created:
        try:
            created = datetime.fromisoformat(vulnerability.created)
            vulnerability.created = created
        except:
            vulnerability.created = None
    if vulnerability.published:
        try:
            published = datetime.fromisoformat(vulnerability.published)
            vulnerability.published = published
        except:
            vulnerability.published = None
            
    if vulnerability.updated:
        try:
            updated = datetime.fromisoformat(vulnerability.updated)
            vulnerability.updated = updated
        except:
            vulnerability.updated = None



    return vulnerability

def check_file(path:Path) -> bool:
    if not path.exists():
        return True
    else:
        x = input('File exists. Overwrite? (Y/N): ').lower() in ['y', 'yes']
        return x

def get_cwes(input:str) -> list:
    # Extract CWEs from a csv in the format [CWE, CWE, ...] 
    # "CWE" is of the format CWE-"number" or "number"
    stripcode = 'CWE-'
    cwe_rm_brackets = input.strip('[]')
    cwe_list = cwe_rm_brackets.split(',')
    cwe_map_trim = map(lambda x:x.strip(), cwe_list)
    cwe_list_trim = list(cwe_map_trim)
    cwe_list_num = [int(x.strip(stripcode)) for x in cwe_list_trim if x.strip(stripcode).isnumeric()]
    return cwe_list_num

def get_reference(csv_data:pd.Series, config_data:dict) -> VulnerabilityReference | None:
    # Get reference in the form of a VulnerabilityReference
    id = source_url = source_name = None
    source_data = config_data.get('source')
    id = get_val('id', csv_data, config_data)
    source_data = config_data.get('source')
    source_url = get_val('url', csv_data, source_data)
    source_name = get_val('name', csv_data, source_data)
    if id or source_name or source_url:
        source = VulnerabilitySource(
                                        url=XsUri(source_url) if source_url else None, 
                                        name=source_name
                                    )
        


        return VulnerabilityReference(
            id=id,
            source=source
        )

    else:
        return None
    
def get_rating(csv_data:pd.Series, config_data:dict) -> VulnerabilityRating:
    valid_sev = ['none', 'info', 'low', 'medium', 'high', 'critical', 'unknown']
    valid_meth = ['CVSSv2', 'CVSSv3', 'CVSSv31', 'CVSSv4', 'OWASP', 'SSVC', 'other']
    source_data = config_data.get('source')
    source_url = get_val('url', csv_data, source_data)
    source_name = get_val('name', csv_data, source_data)
    if source_name and source_url:
        source = VulnerabilitySource(
                                            url=XsUri(source_url) if source_url else None, 
                                            name=source_name
                                        )
    else:
        source =  None
    
    sev_str = get_val('severity', csv_data, config_data)

    if (sev_str) and (sev_str.lower() in valid_sev):
        sev_str = sev_str.lower()
        severity = VulnerabilitySeverity(sev_str)
    else:
        severity = None

    method_str = get_val('method', csv_data, config_data)

    if (method_str) and (method_str in valid_meth):
        method = VulnerabilityScoreSource(method_str)
    else:
        method = None

    score_str = get_val('score', csv_data, config_data)
    if (score_str) and type(score_str) is float:
        score = decimal.Decimal(score_str)
    else:
        score = None

    if source or score or severity or method:
        return VulnerabilityRating(
            source=source,
            score=score,
            severity=severity,
            method=method,
            vector=get_val('vector', csv_data, config_data),
            justification=get_val('justification', csv_data, config_data)
        )

def get_advisory(csv_data:pd.Series, config_data:dict) -> VulnerabilityAdvisory|None:
    title = get_val('title', csv_data, config_data)
    url_str = get_val('url', csv_data, config_data)
    url = XsUri(url_str) if url_str else None
    if url:
        return VulnerabilityAdvisory(
            title=title,
            url=url
        )
    else:
        return None
    
'''
Check if reference string is PURL. 
Then check if PURL is complete. 
If not, garnish PURL with added version information.
Else, continue as normal.
'''
def get_affect(csv_data:pd.Series, config_data:dict) ->list[BomTarget]|None:
    
    is_flawed_purl = False
    refpurl = None

    ref = get_val('ref', csv_data, config_data)
    try:
        refpurl = PackageURL.from_string(ref)
        if not refpurl.version:
            is_flawed_purl = True
    except:
        reference = ref

    reference = ref
   
    ver_list = config_data.get('versions')
    ver_dict_list = [{'version':ver} for ver in ver_list]

    versions = [get_val('version', csv_data, ver) for ver in ver_dict_list]
    versions = [ver for ver in versions if ver is not None]
    versions_list = [BomTargetVersionRange(version=ver) for ver in versions] if any(versions) else None

    
    if is_flawed_purl:
        if versions_list and len(versions_list) > 0:
            target_list = []
            for ver in versions_list:
                new_ref_purl = str(
                                    PackageURL(
                                        type=refpurl.type, 
                                        namespace=refpurl.namespace, 
                                        name=refpurl.name, 
                                        version=ver.version
                                        )
                                )
                

                target_list.append(BomTarget(ref=new_ref_purl, versions=[ver]))

            return target_list if len(target_list) > 0 else None
        else:
            new_ref_purl = str(
                                    PackageURL(
                                        type=refpurl.type, 
                                        namespace=refpurl.namespace, 
                                        name=refpurl.name, 
                                        version= "0"
                                        )
                                )
            return [BomTarget(ref=new_ref_purl)]
           
    if ref:
        return [BomTarget(ref=reference,versions=versions_list)]
    else:
        return None

def get_tool(csv_data:pd.Series, config_data:dict) -> Tool|None:
    name = get_val('name',csv_data, config_data)
    version = get_val('version',csv_data, config_data)
    if name:
        return Tool(
            name=name,
            version=version
        )
    else:
        return None

def get_property(csv_data:pd.Series, val:str) -> Property|None:
    name = val
    conf = {'value':val}
    value = str(get_val('value', csv_data, conf)).lower()
    if name or value:
        return Property(
            name=name,
            value=value
        )
    else:
        return None

def get_credits(csv_data:pd.Series, config_data:dict) -> VulnerabilityCredits | None:
    organizations = config_data.get('organizations')
    individuals = config_data.get('individuals')
    org_list = []
    ind_list = []
    for org in organizations:
        if any(org.values()):
            name = get_val('name',csv_data, org)
            url_list = None
            urls = org.get('urls')
            if urls:
                url_list = [csv_data.get(url) for url in urls]
                url_list = [XsUri(url) for url in url_list if url is not None]
                if url_list == []: url_list = None
                
            contacts = [OrganizationalContact(name=get_val('name', csv_data, cont), email=get_val('email', csv_data, cont), phone=get_val('phone', csv_data, cont)) for cont in org.get('contact') if get_val('name', csv_data, cont)]
            if contacts == []: contacts = None
            if name or url_list or contacts:
                res = OrganizationalEntity(
                    name=name,
                    urls=url_list,
                    contacts=contacts
                )
                org_list.append(res)
    
    for ind in individuals:
        if any(ind.values()):
              res = OrganizationalContact(
                                            name=get_val('name', csv_data, ind), 
                                            email=get_val('email', csv_data, ind), 
                                            phone=get_val('phone', csv_data, ind)
                                        )
              ind_list.append(res)
    
    if org_list and ind_list:
        return VulnerabilityCredits(
            organizations=org_list,
            individuals=ind_list
        )
    else:
        return None

def make_vex(values) -> None:
    #Create VEX file in JSON format. 
    # Schema CycloneDX 1.5

    file = values.get('f')
    config = values.get('c')
    output = values.get('o')

    outfile = Path(output if output else 'vex.json')


    print(f'Reading data file: {file}')

    err, file_data = read_file(file)
    if err != 0:
        print('Error. Bad or missing data file')
        exit(1)
    
    print(f'Reading config file: {config}')

    err, config_data = read_config(config)
    if err != 0:
        print('Error. Bad or missing config file')
        exit(1)

    print('Getting vulnerabilities')

    vulns = []
    for _,i in file_data.iterrows():
       vulns.append(get_vulnerability(i, config_data))

    bom = Bom()

    bom.vulnerabilities = vulns

    bom.metadata.tools.components.add(
                                        Component(
                                                    name="csv2vex",
                                                    version=csv2vex.__version__,
                                                    publisher="CyBeats Technologies Inc",
                                                    type=ComponentType.APPLICATION
                                                )
                                    )
    
    out:BaseOutput = make_outputter(
                                        bom=bom, 
                                        output_format=OutputFormat.JSON, 
                                        schema_version=SchemaVersion.V1_7
                                    )
    
    
    print(f'Creating VEX {outfile.name}')

    x = check_file(outfile)
    if x:
        out.output_to_file(
                                filename=outfile, 
                                allow_overwrite=True, 
                                indent=4
                            )
        print(f'VEX {outfile.name} generated')
    
    else:
        print('Exiting...')


