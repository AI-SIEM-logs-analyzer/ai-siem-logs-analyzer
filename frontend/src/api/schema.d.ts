




export interface paths {
    "/api/alerts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["listAlerts"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/alerts/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: operations["getAlert"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/alerts/{id}/summary": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        



        post: operations["summarizeAlert"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/attack/dataset": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: operations["getAttackDataset"];
        put?: never;
        



        post: operations["importAttackDataset"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/attack/tactics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: operations["listAttackTactics"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/attack/techniques": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["listAttackTechniques"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/auth/login": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
         
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["LoginRequest"];
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["TokenResponse"];
                    };
                };
                 
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/auth/logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
         
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["RefreshRequest"];
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": unknown;
                    };
                };
                 
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/auth/me": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["UserResponse"];
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/auth/refresh": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
         
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["RefreshRequest"];
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["TokenResponse"];
                    };
                };
                 
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/events/search": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["searchEvents"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/logs/upload": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
         
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "multipart/form-data": {
                         
                        file?: string;
                         
                        sourceId?: number;
                        sourceName?: string;
                        sourceType?: components["schemas"]["LogSourceType"];
                    };
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": unknown;
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/logs/uploads": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: {
            parameters: {
                query?: {
                    format?: components["schemas"]["LogFormat"];
                    from?: string;
                    page?: number;
                    size?: number;
                    status?: components["schemas"]["LogUploadStatus"];
                    to?: string;
                    uploadedBy?: string;
                };
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["PageResponseLogUploadResponse"];
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/logs/uploads/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    id: number;
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["LogUploadResponse"];
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/users": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["UserResponse"][];
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
         
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["CreateUserRequest"];
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": unknown;
                    };
                };
                 
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/users/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    id: number;
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["UserResponse"];
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
         
        put: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    id: number;
                };
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["UpdateUserRequest"];
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["UserResponse"];
                    };
                };
                 
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        post?: never;
         
        delete: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    id: number;
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": unknown;
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/users/{id}/password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
         
        put: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    id: number;
                };
                cookie?: never;
            };
            requestBody: {
                content: {
                    "application/json": components["schemas"]["ChangePasswordRequest"];
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": unknown;
                    };
                };
                 
                400: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/logs/upload": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
         
        post: {
            parameters: {
                query?: never;
                header?: never;
                path?: never;
                cookie?: never;
            };
            requestBody: {
                content: {
                    "multipart/form-data": {
                         
                        file?: string;
                         
                        sourceId?: number;
                        sourceName?: string;
                        sourceType?: components["schemas"]["LogSourceType"];
                    };
                };
            };
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": unknown;
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/logs/upload/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
         
        get: {
            parameters: {
                query?: never;
                header?: never;
                path: {
                    id: number;
                };
                cookie?: never;
            };
            requestBody?: never;
            responses: {
                 
                200: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content: {
                        "application/json": components["schemas"]["LogUploadResponse"];
                    };
                };
                 
                401: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
                 
                403: {
                    headers: {
                        [name: string]: unknown;
                    };
                    content?: never;
                };
            };
        };
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/q/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["microprofile_health_root"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/q/health/live": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["microprofile_health_liveness"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/q/health/ready": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["microprofile_health_readiness"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/q/health/started": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        



        get: operations["microprofile_health_startup"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        AlertEventResponse: {
             
            eventId?: number;
             
            sourceId?: number;
            sourceName?: string;
            occurredAt?: components["schemas"]["Instant"];
            ingestedAt?: components["schemas"]["Instant"];
            severity?: components["schemas"]["Severity"];
            message?: string;
            raw?: string;
            fields?: {
                [key: string]: unknown;
            };
        };
        AlertResponse: {
             
            id?: number;
            title?: string;
            detail?: string;
            severity?: components["schemas"]["Severity"];
            status?: components["schemas"]["AlertStatus"];
            raisedAt?: components["schemas"]["Instant"];
            statusChangedAt?: components["schemas"]["Instant"];
            resolvedAt?: components["schemas"]["Instant"];
             
            ruleId?: number;
            ruleName?: string;
            groupKey?: {
                [key: string]: unknown;
            };
            aggregateValue?: number;
             
            eventCount?: number;
            windowStart?: components["schemas"]["Instant"];
            windowEnd?: components["schemas"]["Instant"];
            trigger?: components["schemas"]["AlertEventResponse"];
            aiSummary?: components["schemas"]["AlertSummaryResponse"];
            techniques?: components["schemas"]["AlertTechniqueResponse"][];
        };
         
        AlertStatus: "NEW" | "IN_PROGRESS" | "RESOLVED" | "FALSE_POSITIVE";
        AlertSummaryResponse: {
            severity?: components["schemas"]["Severity"];
            attackType?: components["schemas"]["AttackType"];
            summary?: string;
            recommendedAction?: string;
            evidence?: string[];
            model?: string;
            summarizedAt?: components["schemas"]["Instant"];
        };
        AlertTechniqueResponse: {
            id?: string;
            name?: string;
            url?: string;
            tactics?: components["schemas"]["AttackTacticRefResponse"][];
            source?: components["schemas"]["TechniqueSource"];
        };
        AttackDatasetResponse: {
            version?: string;
            sha256?: string;
             
            techniqueCount?: number;
            importedAt?: components["schemas"]["Instant"];
        };
        AttackTacticRefResponse: {
            id?: string;
            name?: string;
        };
        AttackTacticResponse: {
            id?: string;
            name?: string;
            shortname?: string;
            url?: string;
        };
        AttackTechniqueResponse: {
            id?: string;
            name?: string;
            parentId?: string;
            url?: string;
            tactics?: components["schemas"]["AttackTacticRefResponse"][];
        };
         
        AttackType: "BRUTE_FORCE" | "CREDENTIAL_STUFFING" | "SQL_INJECTION" | "PATH_TRAVERSAL" | "CROSS_SITE_SCRIPTING" | "COMMAND_INJECTION" | "REMOTE_CODE_EXECUTION" | "RECONNAISSANCE" | "DENIAL_OF_SERVICE" | "PRIVILEGE_ESCALATION" | "DATA_EXFILTRATION" | "MALWARE" | "ANOMALOUS_BEHAVIOUR" | "BENIGN" | "OTHER";
        ChangePasswordRequest: {
            password: string;
        };
        CreateUserRequest: {
            username: string;
            email?: string;
            password: string;
            roles: components["schemas"]["Role"][];
        };
        EventFacets: {
            bySeverity?: {
                [key: string]: number;
            };
            bySourceId?: {
                [key: string]: number;
            };
            byHost?: {
                [key: string]: number;
            };
            bySrcIp?: {
                [key: string]: number;
            };
            byStatus?: {
                [key: string]: number;
            };
            topErrors?: {
                [key: string]: number;
            };
            overTime?: components["schemas"]["TimeBucket"][];
            srcIpOverTime?: {
                [key: string]: components["schemas"]["TimeBucket"][];
            };
        };
         
        EventHit: {
             
            eventId?: number;
             
            sourceId?: number;
            occurredAt?: components["schemas"]["Instant"];
            ingestedAt?: components["schemas"]["Instant"];
            severity?: components["schemas"]["Severity"];
            message?: string;
            raw?: string;
             
            fields?: {
                [key: string]: unknown;
            };
        };
         
        EventSearchResponse: {
            hits?: components["schemas"]["EventHit"][];
            



            totalHits?: number;
             
            nextCursorOccurredAt?: ((string | components["schemas"]["Instant"] | null) | null) | components["schemas"]["Instant"] | null;
            



            nextCursorEventId?: number | null;
             
            facets?: components["schemas"]["EventFacets"];
        };
        



        Instant: string;
         
        LogFormat: "JSON" | "SYSLOG" | "CEF" | "CSV" | "ACCESS_LOG" | "PLAIN";
         
        LogSourceType: "SYSLOG" | "FIREWALL" | "CLOUD_TRAIL" | "APPLICATION" | "ENDPOINT";
        LogUploadResponse: {
             
            id?: number;
             
            sourceId?: number;
            sourceName?: string;
            fileName?: string;
            contentType?: string;
            detectedFormat?: components["schemas"]["LogFormat"];
             
            fileSize?: number;
            checksum?: string;
            status?: components["schemas"]["LogUploadStatus"];
            storagePath?: string;
            uploadedBy?: string;
             
            uploadedById?: number;
            createdAt?: components["schemas"]["Instant"];
            processingStartedAt?: components["schemas"]["Instant"];
            processedAt?: components["schemas"]["Instant"];
             
            eventCount?: number;
            errorMessage?: string;
            updatedAt?: components["schemas"]["Instant"];
        };
         
        LogUploadStatus: "PENDING" | "PROCESSING" | "INGESTED" | "FAILED";
        LoginRequest: {
            username: string;
            password: string;
        };
        PageResponseAlertResponse: {
            items?: components["schemas"]["AlertResponse"][];
             
            page?: number;
             
            size?: number;
             
            total?: number;
        };
        PageResponseLogUploadResponse: {
            items?: components["schemas"]["LogUploadResponse"][];
             
            page?: number;
             
            size?: number;
             
            total?: number;
        };
        RefreshRequest: {
            refreshToken: string;
        };
         
        Role: "ADMIN" | "ANALYST" | "VIEWER";
         
        Severity: "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";
         
        TechniqueSource: "RULE" | "AI";
        TimeBucket: {
            start?: components["schemas"]["Instant"];
             
            count?: number;
        };
        TokenResponse: {
            accessToken?: string;
            refreshToken?: string;
            tokenType?: string;
             
            expiresIn?: number;
        };
        UpdateUserRequest: {
            email?: string;
            roles: components["schemas"]["Role"][];
            enabled?: boolean;
        };
        UserResponse: {
             
            id?: number;
            username?: string;
            email?: string;
            roles?: components["schemas"]["Role"][];
            enabled?: boolean;
            passwordSet?: boolean;
            createdAt?: components["schemas"]["Instant"];
            updatedAt?: components["schemas"]["Instant"];
        };
        HealthResponse: {
            checks?: components["schemas"]["HealthCheck"][];
             
            status?: "UP" | "DOWN";
        };
        HealthCheck: {
            data?: Record<string, unknown> | null;
            name?: string;
             
            status?: "UP" | "DOWN";
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    listAlerts: {
        parameters: {
            query?: {
                 
                page?: number;
                 
                severity?: components["schemas"]["Severity"][];
                 
                size?: number;
                 
                status?: components["schemas"]["AlertStatus"][];
                 
                tactic?: string[];
                 
                technique?: string[];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PageResponseAlertResponse"];
                };
            };
             
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getAlert: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertResponse"];
                };
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    summarizeAlert: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AlertResponse"];
                };
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            502: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getAttackDataset: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AttackDatasetResponse"];
                };
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    importAttackDataset: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": string;
                "application/gzip": string;
                "application/octet-stream": string;
            };
        };
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AttackDatasetResponse"];
                };
            };
             
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    listAttackTactics: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AttackTacticResponse"][];
                };
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    listAttackTechniques: {
        parameters: {
            query?: {
                 
                inUse?: boolean;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AttackTechniqueResponse"][];
                };
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    searchEvents: {
        parameters: {
            query?: {
                 
                cursorEventId?: number;
                 
                cursorOccurredAt?: string;
                 
                facets?: boolean;
                



                from?: string;
                 
                order?: "asc" | "desc";
                



                q?: string;
                 
                severity?: components["schemas"]["Severity"][];
                 
                size?: number;
                 
                sourceId?: number[];
                



                srcIp?: string[];
                



                status?: string[];
                



                substring?: string;
                



                to?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EventSearchResponse"];
                };
            };
             
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
             
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    microprofile_health_root: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            500: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    microprofile_health_liveness: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            500: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    microprofile_health_readiness: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            500: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    microprofile_health_startup: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
             
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            500: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
             
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
}
