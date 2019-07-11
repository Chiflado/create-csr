import { Component, OnInit } from '@angular/core';
import { CreateCertificateParams, createCertificate } from './generateCert';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {
  title = 'cert';
  generated;

  ngOnInit() {
    const createdCertParams: CreateCertificateParams = {
      organization: 'TestOrg',
      organizationUnit: 'TestOrgUnit',
      email: 'test@mail.com'
    };
    this.generated = createCertificate(createdCertParams);
    console.log(this.generated);
  }
}
