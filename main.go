package main

import(
	"strconv"
	"golang.org/x/net/context" 
	"database/sql"
        "fmt"
	"time"
	"reflect"
	 _ "encoding/json"
       _ "github.com/mattn/go-sqlite3"
          "gopkg.in/olivere/elastic.v5"
)

const (  
    indexName    = "opsmfelicity-dev-2017-10-26"
    docType      = "vulnRecord"
    appName      = "cVECPE"
    indexMapping = `{
                        "mappings" : {
                            "vulnRecord" : {
                                "properties" : {
                                    "CVEID" : { "type" : "string", "index" : "not_analyzed" },
                                    "CVESummary" : { "type" : "string", "index" : "analyzed" },
                                    "CPEName" : { "type" : "string" },
				    "CPEVendor" : { "type" : "string"},
				    "CPEProduct" : { "type" : "string"},
				    "timestamp" : {"type" : "string", "index": "analyzed"}
                                }
                            }
                        }
                    }`
)



type CVECPEData struct{
	Cveid	string	`json:"CVEID,omitempty"`
	Cvesummary	string	`json:"CVESummary,omitempty"`
	Cpename	string	`json:"CPEName,omitempty"`
	Cpevendor	string	`json:"CPEVendor,omitempty"`
	Cpeproduct	string	`json:"CPEProduct,omitempty"`
	Timestamp	string	`json:"timestamp,omitempty"`
}


func PopulateDataArray() []CVECPEData{
	 db, err := sql.Open("sqlite3", "./cve.sqlite3")
        if err != nil {
                fmt.Println(err.Error())
        }

rows, err := db.Query("select nvd.cve_id as cveid, nvd.summary as cvesummary, cpe.cpe_name as cpename, cpe.vendor as cpevendor, cpe.product as cpeproduct from nvds nvd, cpes cpe where cpe.nvd_id = nvd.id")

        if err != nil {
                fmt.Println(err.Error())
        }

        var cveid string
        var cvesummary string
        var cpename string
        var cpevendor string
        var cpeproduct string

        var dataArray []CVECPEData

        for rows.Next() {
            err = rows.Scan(&cveid, &cvesummary, &cpename, &cpevendor, &cpeproduct)
            if err != nil {
                fmt.Println(err.Error())
            } else {
                var tempObj     CVECPEData
		tempObj.Timestamp = time.Now().Format(time.RFC3339)
                tempObj.Cveid = cveid
                tempObj.Cvesummary = cvesummary
                tempObj.Cpename = cpename
                tempObj.Cpevendor = cpevendor
                tempObj.Cpeproduct = cpeproduct
                dataArray = append(dataArray, tempObj)
            }
        }

        rows.Close()
        db.Close()
	return dataArray
}

func main(){

	// Call a Function that will read all the sqlite3 data 
	DataArr := PopulateDataArray()
	// Call a function that will dump it into elasticsearch

	client, err := elastic.NewClient(elastic.SetURL("http://192.168.2.254:60920"),elastic.SetSniff(false))
	if err != nil {
		fmt.Println(err.Error())
	}
	exists, err := client.IndexExists(indexName).Do(context.Background())
	if err != nil {
    		panic(err)
	}
	if !exists {
		createIndex, err := client.CreateIndex(indexName).Body(indexMapping).Do(context.Background())
   		if err != nil {
        		panic(err)
    		}
    		if !createIndex.Acknowledged {
       			 // Not acknowledged
    		} else {
			fmt.Println("Created Index")
		}
   	}

	for idx,valx := range DataArr {
		fmt.Println(reflect.TypeOf(valx))
		_, err := client.Index().Index(indexName).Type(docType).Id(strconv.Itoa(idx)+"_datafrom2016").BodyJson(valx).Do(context.Background())
		if err != nil {
			fmt.Println(idx)
			fmt.Println(err.Error())
		}

	}
}



