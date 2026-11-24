export type Finding={id:string;title:string;severity:string;confidence:string;evidence:string;recommendation:string};
export type CommonFindingLocation={kind:"url";value:string}|{kind:"file";path:string;line?:number};
export type CommonSecurityFinding={finding_id:string;check_id:string;source:"website"|"repository";target:string;location:CommonFindingLocation;title:string;category:string;severity:string;confidence:string;validation_state:"observed"|"suspected"|"validated"|"inconclusive"|"not_observed"|"not_tested";evidence:string;impact:string|null;preconditions:string[];remediation:string;scanner_version:string;scope_id:string|null;observed_at?:string};
export type Page={url:string;status_code?:number|null;title?:string|null;links:string[];scripts:string[];stylesheets:string[];images:string[];metadata:Record<string,string>};
export type PageEdge={source:string;target:string};
export type ScanHistoryItem={id:string;requested_url:string;final_url:string;title:string|null;status_code:number;scanned_at:string};
export type RouteReference={url:string;line:number;confidence:"high"|"medium"|"low";context:string;dynamic_template_prefix:boolean;evidence:string;method?:string};
export type LibraryEvidence={name:string;confidence:string;evidence:string;offset:number};
export type SourceMapReference={reference:string;line:number};
export type ScriptAnalysis={url:string;bytes_analyzed?:number;line_count?:number;routes?:string[];route_references?:RouteReference[];possible_libraries?:string[];library_evidence?:LibraryEvidence[];source_mapping_url_reference?:boolean;source_map_references?:SourceMapReference[];method?:string;limitations?:string;error?:string};
export type ScanResult={id:string;requested_url:string;final_url:string;status_code:number;scanned_at:string;title?:string|null;description?:string|null;headers:Record<string,string>;technologies:{name:string;confidence:string;evidence:string}[];assets:{kind:string;url:string}[];page:Page;pages:Page[];edges:PageEdge[];findings:Finding[];security_findings?:CommonSecurityFinding[];js_analysis:ScriptAnalysis[];notes:string[];reconstruction?:Record<string,string>|null};

export type RepositoryFinding={id:string;category:string;title:string;severity:string;confidence:string;path:string;line:number;validation_state:"suspected";evidence:string;recommendation:string};
export type RepositoryRoute={method:string;path:string;source_path:string;line:number;syntax:string};
export type DependencyRecord={name:string;ecosystem:string;source_path:string;source_type:string;version_constraint?:string|null;resolved_version?:string|null;dependency_group:string};
export type RepositoryReport={repository:string;scanner_version:string;findings:RepositoryFinding[];security_findings?:CommonSecurityFinding[];route_inventory?:RepositoryRoute[];route_count?:number;route_inventory_truncated?:boolean;dependency_inventory:DependencyRecord[];dependency_count:number;dependency_inventory_truncated:boolean;files_scanned:number;bytes_scanned:number;skipped_files:number;truncated:boolean;limitations:string[];source?:{provider:string;full_name:string;requested_ref:string;default_branch?:string|null;commit_sha:string;archive_bytes:number}};


export type AdvisoryReport={provider:string;packages_checked:number;packages_with_advisories:number;advisory_matches:number;results:{package:string;ecosystem:string;version:string;advisory_count:number;truncated:boolean;advisories:{id:string;summary:string;aliases:string[];modified:string|null;published:string|null;references:string[]}[]}[];limitations:string[]};
